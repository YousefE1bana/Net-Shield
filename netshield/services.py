"""Narrow local sshd journal adapter; never infer auth failure from a SYN."""

import json
import re
import subprocess
import os
import stat
import time
from .events import Origin, host

FAILED_PASSWORD = re.compile(
    r"^Failed password for (?:invalid user )?.+? from ([0-9a-fA-F:.]+) port [0-9]+(?: ssh2)?$"
)


def ssh_outcome(record, target):
    if (
        not isinstance(record, dict)
        or record.get("_COMM") != "sshd"
        or record.get("_UID") != "0"
        or record.get("_SYSTEMD_UNIT") not in ("ssh.service", "sshd.service")
    ):
        return None
    message = record.get("MESSAGE", "")
    if not isinstance(message, str) or len(message) > 4096:
        return None
    match = FAILED_PASSWORD.fullmatch(message)
    if not match:
        return None
    return {
        "kind": "ssh_auth",
        "source_ip": host(match[1]),
        "target_ip": host(target),
        "target_port": 22,
        "outcome": "failure",
        "event_time": int(record["__REALTIME_TIMESTAMP"]) / 1000000,
        "component": "sshd-journal",
    }


def observe_ssh(pipeline, target):
    target = host(target)
    # Trusted journal metadata comes from systemd, not caller-controlled JSON API.
    with subprocess.Popen(
        [
            "/usr/bin/journalctl",
            "--follow",
            "--lines=0",
            "--output=json",
            "--unit=ssh.service",
            "--unit=sshd.service",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ) as process:
        try:
            while line := process.stdout.readline(16385):
                if len(line) > 16384:
                    while line and not line.endswith("\n"):
                        line = process.stdout.readline(16385)
                    pipeline.parser_failures += 1
                    continue
                try:
                    value = ssh_outcome(json.loads(line), target)
                    if value:
                        pipeline.service(value, Origin.SERVICE_EVENT)
                except (ValueError, KeyError, TypeError):
                    pipeline.parser_failures += 1
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def import_web_events(pipeline, path):
    """Bounded local batch contract from a root-owned producer spool.

    No upload endpoint. The producer must validate its own authentication
    outcomes; this adapter never accepts caller-supplied provenance or passwords.
    """
    if os.name != "posix":
        raise ValueError("Trusted service spool requires Linux owner validation")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size > 20 * 1024 * 1024
        ):
            raise ValueError("Web service spool must be a root-owned non-writable regular file <=20 MiB")
        start = time.monotonic()
        count = 0
        while line := stream.readline(16385):
            if len(line) > 16384 or count >= 10000 or time.monotonic() - start > 120:
                raise ValueError("Service batch budget exceeded")
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("kind") not in ("web_auth", "http_request"):
                raise ValueError("Web spool accepts only the trusted web_auth/http_request contract")
            pipeline.service(value, Origin.SERVICE_EVENT)
            count += 1
    pipeline.store.audit("local-cli", "service.web_imported", "root-owned-spool", "success", records=count)
    return {"processed": count, "origin": "service_event", "credentials_retained": False}
