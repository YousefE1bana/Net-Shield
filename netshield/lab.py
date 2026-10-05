"""Explicit Linux-only validation inside newly owned, unrouted namespaces.

Fixed topology and fixed bounded connections. No target, URL, interface, command,
NAT, default route or host firewall parameter is accepted. Root authorization is
required; this module is never imported or called by the web scenario endpoint.
"""

import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from .events import Origin
from .helper import NftBoundary
from .investigations import Investigations
from .pipeline import Pipeline
from .reports import Reports
from .response import Response

CLIENT = "10.77.0.2"
VICTIM = "10.77.0.10"
IP = "/usr/sbin/ip"


def authorized(value):
    if value is not True or platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError(
            "Isolated lab requires Linux root and --authorize-owned-namespace on an operator-owned lab VM"
        )


def command(arguments, input=None, timeout=5):
    result = subprocess.run(
        arguments, input=input, text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise OSError("Owned namespace operation failed")
    return result.stdout


def run_lab(store, settings, authorize=False):
    authorized(authorize)
    record = store.put(
        "lab_runs",
        {
            "origin": "isolated_lab",
            "scenario": "owned-namespace-scan",
            "status": "RUNNING",
            "actor": "local-cli",
            "started_at": time.time(),
            "budget": 18,
            "processed": 0,
            "expected_rules": ["NS-RECON-VERTICAL"],
            "response": "Explicit namespace-only kernel validation; no live host authority",
            "network_access": "Owned veth only",
        },
    )
    record["run_id"] = record["id"]
    token = uuid.uuid4().hex[:10]
    attacker, victim = "ns-a-" + token, "ns-v-" + token
    left, right = "na" + token, "nv" + token
    namespaces = []
    action = None
    links = []
    children = []
    start = time.monotonic()

    def bounded(arguments, input=None, timeout=5):
        remaining = 120 - (time.monotonic() - start)
        if remaining <= 0:
            raise ValueError("Isolated lab wall-time budget reached")
        return command(arguments, input, min(timeout, remaining))

    store.audit(
        "local-cli", "isolated_lab.authorized", record["id"], "RUNNING", namespaces=[attacker, victim]
    )
    try:
        if any(x in bounded([IP, "netns", "list"]).split() for x in (attacker, victim)):
            raise ValueError("Generated namespace collision; no existing namespace will be adopted")
        for name in (attacker, victim):
            bounded([IP, "netns", "add", name])
            namespaces.append(name)
        bounded([IP, "link", "add", left, "type", "veth", "peer", "name", right])
        links.extend([left, right])
        bounded([IP, "link", "set", left, "netns", attacker])
        links.remove(left)
        bounded([IP, "link", "set", right, "netns", victim])
        links.remove(right)
        for name, interface, address in ((attacker, left, CLIENT), (victim, right, VICTIM)):
            bounded([IP, "-n", name, "link", "set", "lo", "up"])
            bounded([IP, "-n", name, "address", "add", address + "/24", "dev", interface])
            bounded([IP, "-n", name, "link", "set", interface, "up"])
            routes = json.loads(bounded([IP, "-n", name, "-j", "route", "show"]))
            if any(r.get("dst") == "default" or r.get("gateway") for r in routes):
                raise ValueError("Unexpected lab route; validation refused")
        with tempfile.TemporaryDirectory(prefix="netshield-lab-", dir=settings.data_dir) as directory:
            os.chmod(directory, 0o700)
            directory = Path(directory)
            capture = directory / "capture.pcap"

            def child(namespace, role, *args):
                return [
                    IP,
                    "netns",
                    "exec",
                    namespace,
                    sys.executable,
                    "-m",
                    "netshield.lab",
                    role,
                    *map(str, args),
                ]

            server = subprocess.Popen(
                child(victim, "server", directory / "server.ready"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            children.append(server)
            wait_ready(directory / "server.ready", server)
            baseline = json.loads(bounded(child(attacker, "probe")))
            if not baseline["connected"]:
                raise ValueError("Disposable baseline service unavailable")
            collector = subprocess.Popen(
                child(victim, "capture", right, capture), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            children.append(collector)
            wait_ready(Path(str(capture) + ".ready"), collector)
            bounded(child(attacker, "generate"), timeout=10)
            collector.wait(timeout=10)
            if collector.returncode:
                raise ValueError("Lab capture failed")
            from scapy.all import PcapReader

            pipeline = Pipeline(store, settings)
            observed = set()
            captured = 0
            with PcapReader(str(capture)) as packets:
                for packet in packets:
                    if captured >= 300:
                        raise ValueError("Lab capture budget exceeded")
                    result = pipeline.packet(packet, Origin.ISOLATED_LAB, record["id"], right)
                    observed.update(a["rule_id"] for a in result["alerts"])
                    captured += 1
            record.update(processed=18, captured_packets=captured, observed_rules=sorted(observed))
            if "NS-RECON-VERTICAL" not in observed:
                raise ValueError("Expected scan detector did not fire")
            alerts = store.list("alerts", {"run": record["id"], "rule": "NS-RECON-VERTICAL"}, limit=1)[
                "items"
            ]
            alert = alerts[0]

            def nft(arguments, input=None):
                result = bounded([IP, "netns", "exec", victim, "/usr/sbin/nft", *arguments], input)
                return json.loads(result) if "-j" in arguments else result

            boundary = NftBoundary(["10.77.0.0/24"], [VICTIM + "/32", "127.0.0.0/8", "::1/128"], nft)
            boundary.initialize()
            broker = Response(store, settings)
            action = store.put(
                "actions",
                {
                    "origin": "isolated_lab",
                    "run_id": record["id"],
                    "target_ip": CLIENT,
                    "alert_id": alert["id"],
                    "incident_id": alert["incident_id"],
                    "status": "REQUESTED",
                    "requested_by": "local-cli",
                    "reason": "Explicit owned namespace closed-loop scan validation",
                    "created_at": time.time(),
                    "ttl": 60,
                    "expires_at": time.time() + 60,
                    "backend": "nftables",
                    "dry_run": False,
                    "verification": "not_enforced",
                    "helper_scope": "Namespace " + victim + " only",
                    "history": [],
                },
            )
            broker.transition(action, "VALIDATED")
            broker.transition(action, "APPLYING")
            evidence = boundary.request("add", CLIENT, 60)
            if CLIENT not in evidence["targets"]:
                raise ValueError("Namespace kernel presence not verified")
            broker.transition(action, "APPLIED", verification="kernel_present", verified_at=time.time())
            blocked = json.loads(bounded(child(attacker, "probe")))
            if blocked["connected"]:
                raise ValueError("Blocked namespace connectivity was unexpectedly available")
            deadline = time.monotonic() + 68
            while CLIENT in boundary.request("list")["targets"]:
                if time.monotonic() > deadline:
                    raise ValueError("Kernel expiry not verified within bounded wait")
                time.sleep(1)
            broker.transition(action, "EXPIRING")
            absent = boundary.request("remove", CLIENT)
            if CLIENT in absent["targets"]:
                raise ValueError("Namespace removal verification failed")
            restored = json.loads(bounded(child(attacker, "probe")))
            if not restored["connected"]:
                raise ValueError("Post-expiry namespace connectivity not restored")
            broker.transition(
                action,
                "REMOVED",
                verification="kernel_absent",
                verified_at=time.time(),
                removal_reason="Kernel TTL expired; connectivity restored",
            )
            investigation = Investigations(store, settings)
            investigation.change(
                "incidents",
                alert["incident_id"],
                {
                    "status": "RESOLVED",
                    "note": "Owned namespace kernel presence, blocked connectivity, TTL absence and restored connectivity verified. No host firewall modified.",
                },
                "local-cli",
            )
            reports = Reports(store)
            output = settings.data_dir / ("isolated-lab-" + record["id"] + ".pdf")
            with output.open("xb") as file:
                file.write(reports.pdf(reports.snapshot(alert["incident_id"])))
            output.chmod(0o600)
            record.update(
                status="PASS",
                incident_id=alert["incident_id"],
                action_id=action["id"],
                report=str(output),
                assertions=[
                    {"rule": "Scan detection + namespace kernel apply/expiry/connectivity", "passed": True}
                ],
            )
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, KeyboardInterrupt) as error:
        record.update(status="INCOMPLETE", error=type(error).__name__, error_reason=str(error)[:160])
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        cleanup = []
        for interface in links:
            try:
                command([IP, "link", "delete", interface])
            except (OSError, subprocess.SubprocessError):
                cleanup.append(interface)
        for name in reversed(namespaces):
            try:
                command([IP, "netns", "delete", name])
            except (OSError, subprocess.SubprocessError):
                cleanup.append(name)
        record.update(
            cleanup_remaining=cleanup, finished_at=time.time(), elapsed_seconds=time.monotonic() - start
        )
        if cleanup:
            record["status"] = "INCOMPLETE"
        if action and action["status"] != "REMOVED":
            Response(store, settings).transition(
                action,
                "UNKNOWN" if victim in cleanup else "REMOVED",
                verification="unavailable" if victim in cleanup else "namespace_destroyed",
                removal_reason="Owned lab teardown; no host helper called",
            )
        store.put("lab_runs", record)
        store.audit(
            "local-cli", "isolated_lab.finished", record["id"], record["status"], cleanup_remaining=cleanup
        )
    return record


def wait_ready(path, process):
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            raise ValueError("Lab child did not become ready")
        time.sleep(0.05)


def child_main():
    # Internal fixed-role workers. They operate in the caller's namespace; no
    # worker accepts a remote target or requests firewall/capture outside it.
    role = sys.argv[1]
    if platform.system() != "Linux":
        raise ValueError("Lab workers require Linux namespaces")
    namespace = command([IP, "netns", "identify", str(os.getpid())]).strip()
    if not re.fullmatch(r"ns-[av]-[0-9a-f]{10}", namespace):
        raise ValueError("Fixed lab workers refuse the host namespace")
    if role in ("server", "capture") and not namespace.startswith("ns-v-"):
        raise ValueError("Victim worker outside the owned victim namespace")
    if role in ("probe", "generate") and not namespace.startswith("ns-a-"):
        raise ValueError("Client worker outside the owned client namespace")
    if role == "server":
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((VICTIM, 9090))
            server.listen(4)
            server.settimeout(1)
            Path(sys.argv[2]).touch(exist_ok=False)
            deadline = time.monotonic() + 115
            while time.monotonic() < deadline:
                try:
                    with server.accept()[0] as client:
                        client.settimeout(0.5)
                        client.sendall(b"NetShield owned lab\n")
                except (socket.timeout, ConnectionError):
                    pass
    elif role == "probe":
        connected = False
        with socket.socket() as client:
            client.settimeout(1)
            client.bind((CLIENT, 0))
            try:
                client.connect((VICTIM, 9090))
                connected = client.recv(64).startswith(b"NetShield")
            except OSError:
                pass
        print(json.dumps({"connected": connected}))
    elif role == "generate":
        for port in range(8000, 8018):
            with socket.socket() as client:
                client.settimeout(0.1)
                client.bind((CLIENT, 0))
                try:
                    client.connect((VICTIM, port))
                except OSError:
                    pass
            time.sleep(0.05)
    elif role == "capture":
        from scapy.all import sniff, wrpcap

        output = Path(sys.argv[3])
        if sys.argv[2] != "nv" + namespace[5:]:
            raise ValueError("Capture interface must be the generated victim veth")
        packets = sniff(
            iface=sys.argv[2],
            count=300,
            timeout=5,
            started_callback=lambda: Path(str(output) + ".ready").touch(exist_ok=False),
        )
        wrpcap(str(output), packets)
        output.chmod(0o600)
    else:
        raise ValueError("Unknown fixed lab worker")


if __name__ == "__main__":
    child_main()
