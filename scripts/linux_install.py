"""Canonical install.sh implementation; stdlib works with Ubuntu's bootstrap Python 3.10.

All system commands use argument arrays. Deterministic renderers are portable-testable.
Only installation / explicit helper startup creates resources; verify and dry-run do not.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
STATE = Path("/etc/netshield/install-state.json")
RUNTIME = Path("/opt/netshield/venv/bin/python")
UNITS = (
    "web.service",
    "capture.service",
    "helper.service",
    "maintenance.service",
    "maintenance.timer",
    "proxy.service",
)
SAFE_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8")
)


def run(arguments, capture=True):
    return (
        subprocess.run(
            [str(a) for a in arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        ).stdout
        or ""
    )


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def network(value):
    result = ipaddress.ip_network(value, strict=False)
    if result.prefixlen == 0 or result.is_multicast or result.is_unspecified:
        raise ValueError("Management and response scopes must be bounded literal IP/CIDR values")
    return str(result)


def validate_plan(values, addresses):
    result = dict(values)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", result["capture"] or ""):
        raise ValueError("Capture requires a literal interface name")
    if result["capture"] not in {a["ifname"] for a in addresses}:
        raise ValueError("Capture interface does not exist")
    address = ipaddress.ip_address(result["management"])
    local = {a["local"] for i in addresses for a in i.get("addr_info", [])}
    if str(address) not in local or address.is_unspecified or address.is_loopback or address.is_link_local:
        raise ValueError("Management must be an explicit local, non-loopback, non-link-local address")
    result["management"] = str(address)
    result["clients"] = sorted(set(network(c) for c in result["clients"]))
    if not result["clients"]:
        raise ValueError("At least one explicit management client IP/CIDR is required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", result["sensor"] or ""):
        raise ValueError("Sensor ID requires 1–64 letters, digits, dot, underscore or hyphen")
    hostname = result["hostname"]
    if hostname and (
        len(hostname) > 253
        or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.split(".")
        )
    ):
        raise ValueError("Hostname must be a literal DNS name")
    result["networks"] = sorted(set(network(c) for c in result["networks"]))
    for value in result["networks"]:
        scope = ipaddress.ip_network(value)
        if not any(scope.version == safe.version and scope.subnet_of(safe) for safe in SAFE_NETWORKS):
            raise ValueError("Response scope must be inside explicit RFC1918/ULA lab networks")
    if result["response"] and not result["networks"]:
        raise ValueError("Enabling manual response requires an explicit private response network")
    if result["networks"] and not result["response"]:
        raise ValueError("Response networks require --enable-response")
    return result


def protections(plan, addresses, routes, resolvers):
    protected = {"127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", *plan["clients"]}
    for interface in addresses:
        for item in interface.get("addr_info", []):
            address = ipaddress.ip_address(item["local"])
            protected.add(str(ipaddress.ip_network(str(address))))
            if interface["ifname"] != plan["capture"]:
                protected.add(str(ipaddress.ip_network(f"{address}/{item['prefixlen']}", strict=False)))
    for value in [r["gateway"] for r in routes if "gateway" in r] + list(resolvers):
        protected.add(str(ipaddress.ip_network(value.split("%")[0])))
    return sorted(protected)


def configurations(plan, protected, uid, gid):
    return (
        {
            "data_dir": "/var/lib/netshield",
            "host": "127.0.0.1",
            "port": 8080,
            "secure_cookie": True,
            "interface": plan["capture"],
            "sensor_id": plan["sensor"],
            "trusted_hosts": list(
                dict.fromkeys(
                    ["localhost", "127.0.0.1", "::1", plan["management"]]
                    + ([plan["hostname"]] if plan["hostname"] else [])
                )
            ),
            "response_enabled": plan["response"],
            "auto_response": False,
            "response_networks": plan["networks"],
            "protected_networks": protected,
        },
        {
            "client_uid": uid,
            "client_gid": gid,
            "socket": "/run/netshield/response.sock",
            "allowed_networks": plan["networks"],
            "protected_networks": protected,
        },
    )


def nginx_config(plan):
    address = plan["management"]
    listen = f"[{address}]" if ":" in address else address
    clients = "\n".join("        allow " + n + ";" for n in plan["clients"])
    names = address + (" " + plan["hostname"] if plan["hostname"] else "")
    return f"""# NetShield dedicated instance; no include of global nginx sites.
user www-data;
worker_processes auto;
pid /run/netshield-proxy/nginx.pid;
error_log stderr warn;
events {{ worker_connections 512; }}
http {{
    access_log /dev/stdout;
    server_tokens off;
    client_max_body_size 2m;
    client_body_temp_path /tmp/netshield-client;
    proxy_temp_path /tmp/netshield-proxy;
    server {{
        listen {listen}:443 ssl;
        server_name {names};
        ssl_certificate /etc/netshield/tls/console.crt;
        ssl_certificate_key /etc/netshield/tls/console.key;
        ssl_protocols TLSv1.2 TLSv1.3;
{clients}
        deny all;
        location / {{
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_connect_timeout 5s;
            proxy_read_timeout 30s;
        }}
    }}
}}
"""


def secure_root(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise ValueError("Root ownership / non-writable boundary required: " + str(path))


class ManagedFiles:
    """Hash ledger refuses foreign/edited resources; backups are private and never published."""

    def __init__(self, path=STATE, privileged=True):
        self.path, self.privileged = Path(path), privileged
        if self.path.exists() or self.path.is_symlink():
            if privileged:
                secure_root(self.path)
            self.state = json.loads(self.path.read_text())
            if self.state.get("format") != "netshield-install-v1":
                raise ValueError("Foreign installation ledger")
        else:
            self.state = {"format": "netshield-install-v1", "files": {}, "directories": []}

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("Foreign/stale ledger temporary file; inspect before retry")
        with temporary.open("x", encoding="utf-8") as output:
            os.chmod(temporary, 0o600)
            output.write(json.dumps(self.state, indent=2) + "\n")
        temporary.replace(self.path)

    def check(self, path):
        path = Path(path)
        if path.is_symlink():
            raise ValueError("Refusing symlink: " + str(path))
        if path.exists():
            if self.privileged:
                secure_root(path)
            if str(path) not in self.state["files"]:
                raise ValueError("Foreign file: " + str(path))
            if digest(path) != self.state["files"][str(path)]:
                raise ValueError("Managed file modified; preserve and review before rerun: " + str(path))
        elif str(path) in self.state["files"]:
            raise ValueError("Managed file missing: " + str(path))

    def write(self, path, data, mode, gid=0):
        path = Path(path)
        self.check(path)
        if path.exists() and path.read_bytes() == data:
            if self.privileged and (stat.S_IMODE(path.stat().st_mode) != mode or path.stat().st_gid != gid):
                raise ValueError("Managed file permissions changed: " + str(path))
            return
        if path.exists():
            backup = path.with_name(path.name + f".{time.time_ns()}.bak")
            with backup.open("xb") as output:
                os.chmod(backup, 0o600)
                output.write(path.read_bytes())
        descriptor, name = tempfile.mkstemp(prefix=".netshield-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                os.chmod(name, mode)
                if self.privileged:
                    os.fchown(output.fileno(), 0, gid)
                output.write(data)
            Path(name).replace(path)
        finally:
            Path(name).unlink(missing_ok=True)
        self.state["files"][str(path)] = digest(path)
        self.save()


def discover():
    addresses = json.loads(run(["ip", "-j", "address", "show"]))
    routes = json.loads(run(["ip", "-j", "route", "show", "default"]))
    routes += json.loads(run(["ip", "-j", "-6", "route", "show", "default"]))
    resolvers = []
    for line in Path("/etc/resolv.conf").read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            resolvers.append(str(ipaddress.ip_address(parts[1].split("%")[0])))
    # systemd-resolved often exposes only a stub through resolv.conf.
    if shutil.which("resolvectl"):
        for line in run(["resolvectl", "dns"]).splitlines():
            for word in line.split(": ", 1)[-1].split():
                try:
                    resolvers.append(str(ipaddress.ip_address(word.split("%")[0])))
                except ValueError:
                    pass
    return addresses, routes, resolvers


def select_plan(args, ledger, addresses):
    previous = ledger.state.get("plan")
    fields = {
        "capture": args.capture_interface,
        "management": args.management_ip,
        "clients": args.management_client,
        "sensor": args.sensor_id,
        "hostname": args.hostname,
        "response": args.enable_response,
        "networks": args.response_network,
    }
    if previous:
        candidate = {key: previous[key] if value is None else value for key, value in fields.items()}
        result = validate_plan(candidate, addresses)
        if result != previous or args.cert or args.key:
            raise ValueError("Rerun choices differ from the preserved deployment. Review changes separately.")
        return result
    values = {"hostname": "", "response": False, "networks": []}
    for key, value in fields.items():
        if value is not None:
            values[key] = value
    print(run(["ip", "-brief", "address"]))
    print("Select an observed lab interface. Keep NAT/internet management separate when possible.")
    for key, prompt in (
        ("capture", "Capture interface"),
        ("management", "Local management IP"),
        ("clients", "Allowed management client IP/CIDR"),
        ("sensor", "Sensor ID"),
    ):
        if key not in values:
            if args.non_interactive:
                raise ValueError("Non-interactive first install requires explicit " + key)
            answer = input(prompt + ": ").strip()
            values[key] = [answer] if key == "clients" else answer
    return validate_plan(values, addresses)


def platform_preflight():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError("Linux and root/sudo are required")
    release = dict(
        line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line
    )
    distro, version = release.get("ID", "").strip('"'), release.get("VERSION_ID", "").strip('"')
    if distro != "ubuntu" or version not in {"22.04", "24.04"}:
        raise ValueError("Installer targets Ubuntu 22.04/24.04 only; no generic Linux support claim")
    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemctl"):
        raise ValueError("A booted systemd host is required; a container/chroot is insufficient")
    if not shutil.which("ip"):
        raise ValueError("Install Ubuntu iproute2 before discovery")
    print(f"Platform: Ubuntu {version}, {platform.machine()}, bootstrap {sys.version.split()[0]}")
    return version


def listener_preflight(plan, ledger):
    """Refuse conflicting sockets before apt/build/account/file changes."""
    for line in run(["ss", "-H", "-ltnp"]).splitlines():
        endpoint = line.split()[3]
        if endpoint in {"0.0.0.0:443", "[::]:443", "*:443"}:
            raise ValueError("Existing wildcard HTTPS listener conflicts with the management profile")
        if endpoint.endswith(":8080") or endpoint in {
            plan["management"] + ":443",
            "[" + plan["management"] + "]:443",
        }:
            unit = "web" if endpoint.endswith(":8080") else "proxy"
            if not ledger.state.get("active_runtime"):
                raise ValueError("Foreign listener conflicts with NetShield: " + endpoint)
            pid = run(
                ["systemctl", "show", "netshield-" + unit + ".service", "-p", "MainPID", "--value"]
            ).strip()
            if pid == "0" or "pid=" + pid + "," not in line:
                raise ValueError("Listener does not belong to the managed service: " + endpoint)


def check_account():
    import pwd

    try:
        account = pwd.getpwnam("netshield")
    except KeyError:
        return None
    if (
        account.pw_uid == 0
        or account.pw_gid == 0
        or account.pw_dir != "/var/lib/netshield"
        or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
        or set(os.getgrouplist("netshield", account.pw_gid)) != {account.pw_gid}
    ):
        raise ValueError("Existing netshield account does not meet the isolated service-account contract")
    if run(["id", "-gn", "netshield"]).strip() != "netshield":
        raise ValueError("Existing netshield account must have primary group netshield")
    return account


def resources_preflight(ledger):
    for parent in ("/etc", "/opt", "/var/lib", "/etc/systemd/system"):
        secure_root(parent)
    for name in ("/run/netshield", "/run/netshield-proxy"):
        path = Path(name)
        if path.exists() or path.is_symlink():
            if not ledger.state.get("runtime_directories_managed"):
                raise ValueError("Foreign runtime directory: " + name)
            secure_root(path)
    for name in ("/etc/netshield", "/opt/netshield", "/var/lib/netshield"):
        path = Path(name)
        if path.is_symlink():
            raise ValueError("Refusing deployment directory symlink: " + name)
        if path.exists() and name not in ledger.state["directories"]:
            raise ValueError(
                "Foreign deployment directory; existing manual installation needs review: " + name
            )
        if path.exists():
            if name == "/var/lib/netshield":
                account = check_account()
                if (
                    not account
                    or path.stat().st_uid != account.pw_uid
                    or path.stat().st_gid != account.pw_gid
                ):
                    raise ValueError("Data ownership differs from service account")
                if path.stat().st_mode & 0o077:
                    raise ValueError("Application state must remain private (0700)")
            else:
                secure_root(path)
    for name in ledger.state["files"]:
        ledger.check(name)
    for suffix in UNITS:
        ledger.check(Path("/etc/systemd/system/netshield-" + suffix))
    for path in (
        "/etc/netshield/config.json",
        "/etc/netshield/helper-policy.json",
        "/etc/netshield/nginx.conf",
        "/etc/netshield/tls/console.key",
        "/etc/netshield/tls/console.crt",
    ):
        ledger.check(Path(path))
    active = ledger.state.get("active_runtime")
    link = Path("/opt/netshield/venv")
    if link.exists() or link.is_symlink():
        if not active or not link.is_symlink() or str(link.resolve()) != active:
            raise ValueError("Foreign production runtime link")
        if link.lstat().st_uid != 0:
            raise ValueError("Runtime link is not root-owned")
        secure_root(link.resolve())
    elif active:
        raise ValueError("Managed runtime link is missing")


def choose_python(args, version):
    candidates = (
        [args.python]
        if args.python
        else [
            shutil.which(name) for name in ("python3", "python3.12", "python3.13", "python3.11", "python3.14")
        ]
    )
    for candidate in filter(None, candidates):
        executable = Path(candidate).resolve()
        secure_root(executable)
        for parent in executable.parents:
            secure_root(parent)
        try:
            supported = run([executable, "-I", "-c", "import sys,venv;print(sys.version_info >= (3,11))"])
        except subprocess.CalledProcessError:
            continue
        if supported.strip() == "True":
            # Ubuntu may provide venv.py without its ensurepip wheels.
            try:
                run([executable, "-I", "-c", "import ensurepip"])
            except subprocess.CalledProcessError:
                minor = run(
                    [executable, "-I", "-c", "import sys;print('%d.%d'%sys.version_info[:2])"]
                ).strip()
                if not str(executable).startswith("/usr/bin/python"):
                    raise ValueError("Selected custom Python lacks ensurepip/venv support")
                run(
                    ["apt-get", "install", "-y", "--no-install-recommends", "python" + minor + "-venv"], False
                )
            print("Production Python: " + run([executable, "--version"]).strip())
            return str(executable)
    if args.python:
        raise ValueError("Selected interpreter must be root-owned Python >=3.11 with venv support")
    if version == "22.04":
        permitted = args.allow_deadsnakes
        if not permitted and not args.non_interactive:
            permitted = (
                input(
                    "Jammy Python 3.10 is unsupported. Add third-party deadsnakes PPA for Python 3.12? [y/N]: "
                )
                .strip()
                .lower()
                == "y"
            )
        if not permitted:
            raise ValueError("Install supported Python + venv yourself, or explicitly use --allow-deadsnakes")
        run(["apt-get", "install", "-y", "--no-install-recommends", "software-properties-common"], False)
        run(["add-apt-repository", "--yes", "ppa:deadsnakes/ppa"], False)
        run(["apt-get", "update"], False)
    run(["apt-get", "install", "-y", "--no-install-recommends", "python3.12", "python3.12-venv"], False)
    return "/usr/bin/python3.12"


def ensure_directory(path, ledger, uid=0, gid=0, mode=0o750):
    path = Path(path)
    if path.exists() or path.is_symlink():
        if str(path) not in ledger.state["directories"] or path.is_symlink():
            raise ValueError("Foreign directory: " + str(path))
        info = path.stat()
        if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError("Managed directory ownership/mode changed: " + str(path))
        return
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    ledger.state["directories"].append(str(path))
    ledger.save()


def build_runtime(python, ledger):
    # Root-private scratch space contains only reviewed build inputs, not DB/logs/credentials.
    with tempfile.TemporaryDirectory(prefix="netshield-build-") as scratch:
        scratch = Path(scratch)
        source = scratch / "source"
        source.mkdir()
        for file in ("pyproject.toml", "setup.py", "requirements.txt", "README.md", "LICENSE"):
            shutil.copyfile(ROOT / file, source / file)
        for name in ("netshield", "dashboard"):
            shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        builder = scratch / "builder"
        run([python, "-I", "-m", "venv", builder])
        tool = builder / "bin/python"
        run([tool, "-I", "-m", "pip", "install", "setuptools==82.0.1"], False)
        wheels = scratch / "wheels"
        run(
            [
                tool,
                "-I",
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                wheels,
                source,
            ],
            False,
        )
        (wheel,) = wheels.glob("netshield_ndr-*.whl")
        identity = digest(wheel)
        releases = Path("/opt/netshield/releases")
        ensure_directory(releases, ledger, mode=0o755)
        release = releases / (identity[:20] + "-" + str(time.time_ns()))
        ensure_directory(release, ledger, mode=0o755)
        venv = release / "venv"
        run([python, "-I", "-m", "venv", venv])
        run([venv / "bin/python", "-I", "-m", "pip", "install", wheel], False)
        run([venv / "bin/python", "-I", "-m", "pip", "check"], False)
        shutil.copyfile(wheel, release / wheel.name)
        # No recursive chown of existing resources: all new runtime files were created by root.
        for directory, dirs, files in os.walk(release):
            for item in [Path(directory), *(Path(directory) / n for n in dirs + files)]:
                if not item.is_symlink():
                    os.chmod(item, item.stat().st_mode & ~0o022)
        ledger.state["pending_runtime"] = str(venv)
        ledger.save()
        return venv


def certificate(args, plan, ledger):
    key, cert = Path("/etc/netshield/tls/console.key"), Path("/etc/netshield/tls/console.crt")
    if key.exists() and cert.exists():
        ledger.check(key)
        ledger.check(cert)
    else:
        if bool(args.cert) != bool(args.key):
            raise ValueError("--cert and --key must be supplied together")
        with tempfile.TemporaryDirectory(prefix="netshield-tls-") as directory:
            generated_key, generated_cert = Path(directory) / "key", Path(directory) / "cert"
            if args.cert:
                shutil.copyfile(args.key, generated_key)
                shutil.copyfile(args.cert, generated_cert)
            else:
                san = "IP:" + plan["management"] + (",DNS:" + plan["hostname"] if plan["hostname"] else "")
                run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:3072",
                        "-nodes",
                        "-days",
                        "365",
                        "-subj",
                        "/CN=" + (plan["hostname"] or plan["management"]),
                        "-addext",
                        "subjectAltName=" + san,
                        "-keyout",
                        generated_key,
                        "-out",
                        generated_cert,
                    ]
                )
            validate_certificate(generated_cert, generated_key, plan)
            ledger.write(key, generated_key.read_bytes(), 0o600)
            ledger.write(cert, generated_cert.read_bytes(), 0o644)
    validate_certificate(cert, key, plan)


def validate_certificate(cert, key, plan):
    run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "86400"])
    sans = run(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"])
    # x509 -checkip/-checkhost can exit zero on a mismatch; inspect the result too.
    if "does match certificate" not in run(
        ["openssl", "x509", "-in", cert, "-noout", "-checkip", plan["management"]]
    ):
        raise ValueError("TLS certificate IP SAN does not match management endpoint")
    if plan["hostname"]:
        names = re.findall(r"DNS:([^,\s]+)", sans)
        if plan["hostname"].lower() not in {n.lower() for n in names}:
            raise ValueError("TLS hostname requires an explicit matching DNS SAN")
        if "does match certificate" not in run(
            ["openssl", "x509", "-in", cert, "-noout", "-checkhost", plan["hostname"]]
        ):
            raise ValueError("TLS certificate hostname does not match management endpoint")
    if run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"]) != run(
        ["openssl", "pkey", "-in", key, "-pubout"]
    ):
        raise ValueError("TLS certificate and private key do not match")


def as_service(*arguments):
    return run(["runuser", "-u", "netshield", "--", RUNTIME, "-I", *arguments])


def switch_runtime(venv, ledger):
    link = Path("/opt/netshield/venv")
    temporary = link.with_name(".venv-next")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("Stale/foreign runtime staging link")
    temporary.symlink_to(venv)
    temporary.replace(link)
    ledger.state["previous_runtime"] = ledger.state.get("active_runtime")
    ledger.state["active_runtime"] = str(venv)
    ledger.state.pop("pending_runtime", None)
    ledger.save()


def check_existing_table(python):
    existing = json.loads(run(["nft", "-j", "list", "tables"]))
    if any(
        t.get("table", {}).get("name") == "netshield_v2" and t["table"].get("family") == "inet"
        for t in existing.get("nftables", [])
    ):
        run(
            [
                python,
                "-I",
                "-c",
                "from netshield.helper import NftBoundary; NftBoundary(['10.0.0.0/8'],['127.0.0.0/8']).inspect()",
            ]
        )
        return True
    return False


def verify(ledger):
    """Read-only checks. Never initialize a store, prune, block, replay or mutate a firewall."""
    plan = ledger.state["plan"]
    failures = []

    def check(label, operation):
        try:
            operation()
            print("PASS " + label)
        except (ValueError, OSError, subprocess.CalledProcessError, AssertionError) as error:
            failures.append(label)
            print("FAIL " + label + ": " + str(error))

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    check("managed file ownership/hashes", lambda: resources_preflight(ledger))
    check("installed dependency consistency", lambda: run([RUNTIME, "-I", "-m", "pip", "check"]))
    expected = {
        "web": ("netshield", "", "af_inet af_inet6 af_unix af_netlink"),
        "capture": ("netshield", "cap_net_raw", "af_packet af_inet af_inet6 af_netlink af_unix"),
    }
    if plan["response"]:
        expected["helper"] = ("root", "cap_chown cap_net_admin", "af_unix af_netlink")

    def unit_check(name, user, capabilities, families):
        unit = "netshield-" + name + ".service"
        run(["systemctl", "is-active", "--quiet", unit])
        output = run(
            [
                "systemctl",
                "show",
                unit,
                "-p",
                "User",
                "-p",
                "NoNewPrivileges",
                "-p",
                "CapabilityBoundingSet",
                "-p",
                "AmbientCapabilities",
                "-p",
                "RestrictAddressFamilies",
                "-p",
                "MainPID",
            ]
        )
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require(values["User"] == user, "Unexpected unit User")
        require(values["NoNewPrivileges"] == "yes", "NoNewPrivileges is not enabled")
        require(
            set(values["CapabilityBoundingSet"].split()) == set(capabilities.split()),
            "Unexpected capabilities",
        )
        require(
            set(values["RestrictAddressFamilies"].split()) == set(families.split()),
            "Unexpected address families",
        )
        ambient = "cap_net_raw" if name == "capture" else ""
        require(
            set(values["AmbientCapabilities"].split()) == set(ambient.split()),
            "Unexpected ambient capabilities",
        )
        process = dict(
            line.split(":", 1)
            for line in Path("/proc/" + values["MainPID"] + "/status").read_text().splitlines()
            if ":" in line
        )
        account = check_account()
        expected_uid = 0 if name == "helper" else account.pw_uid
        require({int(v) for v in process["Uid"].split()} == {expected_uid}, "Unexpected runtime UID")
        require(process["NoNewPrivs"].strip() == "1", "Runtime no-new-privileges missing")
        allowed = 0 if name == "web" else 1 << 13 if name == "capture" else (1 << 12) | 1
        actual = int(process["CapEff"].strip(), 16)
        require(actual == allowed, "Unexpected effective process capabilities")

    for name, (user, capabilities, families) in expected.items():
        check(
            name + " service runtime privilege boundary",
            lambda n=name, u=user, c=capabilities, f=families: unit_check(n, u, c, f),
        )
    if not plan["response"]:
        check(
            "helper remains disabled",
            lambda: require(
                run(["systemctl", "show", "netshield-helper.service", "-p", "ActiveState", "--value"]).strip()
                == "inactive",
                "Helper active in observe-only deployment",
            ),
        )
    for name in ("netshield-maintenance.timer", "netshield-proxy.service"):
        check(name + " active", lambda n=name: run(["systemctl", "is-active", "--quiet", n]))
    check(
        "maintenance netlink / no capabilities",
        lambda: require(
            "af_netlink"
            in run(
                [
                    "systemctl",
                    "show",
                    "netshield-maintenance.service",
                    "-p",
                    "RestrictAddressFamilies",
                    "--value",
                ]
            )
            and not run(
                [
                    "systemctl",
                    "show",
                    "netshield-maintenance.service",
                    "-p",
                    "CapabilityBoundingSet",
                    "--value",
                ]
            ).strip(),
            "Maintenance privilege/family mismatch",
        ),
    )
    check("dedicated TLS configuration", lambda: run(["nginx", "-t", "-c", "/etc/netshield/nginx.conf"]))

    def listeners():
        lines = run(["ss", "-H", "-ltnp"]).splitlines()
        web = [line for line in lines if line.split()[3].endswith(":8080")]
        require(
            len(web) == 1 and web[0].split()[3] == "127.0.0.1:8080",
            "Backend is not exclusively loopback:8080",
        )
        tls = [line for line in lines if line.split()[3].endswith(":443")]
        host = plan["management"]
        require(
            any(line.split()[3] in {host + ":443", "[" + host + "]:443"} and "nginx" in line for line in tls),
            "Selected TLS listener missing",
        )
        require(
            not any(line.split()[3] in {"0.0.0.0:443", "[::]:443", "*:443"} for line in tls),
            "Wildcard TLS listener present",
        )

    check("actual loopback backend / selected-IP TLS listeners", listeners)
    check(
        "TLS certificate/key SAN, match and validity",
        lambda: validate_certificate(
            "/etc/netshield/tls/console.crt", "/etc/netshield/tls/console.key", plan
        ),
    )

    def http_check():
        backend = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
        backend.request("GET", "/", headers={"Host": plan["hostname"] or plan["management"]})
        reply = backend.getresponse()
        require(
            reply.status == 302 and reply.getheader("Location", "").startswith("/auth/login"),
            "Expected unauthenticated login redirect",
        )
        backend.close()
        context = ssl.create_default_context()
        context.load_verify_locations(cafile="/etc/netshield/tls/console.crt")
        remote = http.client.HTTPSConnection(plan["management"], 443, timeout=5, context=context)
        remote.request("GET", "/")
        reply = remote.getresponse()
        allowed = any(
            ipaddress.ip_address(plan["management"]) in ipaddress.ip_network(c) for c in plan["clients"]
        )
        require(reply.status == (302 if allowed else 403), "TLS self-probe did not match ACL expectation")
        remote.close()

    check("TLS handshake / local ACL / application auth redirect", http_check)

    def ownership():
        for root in (Path("/opt/netshield"), Path("/etc/netshield")):
            for directory, dirs, files in os.walk(root):
                for item in [Path(directory), *(Path(directory) / n for n in dirs + files)]:
                    secure_root(item.resolve() if item.is_symlink() else item)
        as_service(
            "-c",
            "import os; from pathlib import Path; paths=[Path('/opt/netshield'),Path('/etc/netshield')]; "
            "assert all(not os.access(p,os.W_OK) for root in paths for p in [root,*root.rglob('*')] if not p.is_symlink()); "
            "assert os.access('/var/lib/netshield',os.W_OK)",
        )
        key = Path("/etc/netshield/tls/console.key")
        require(
            key.stat().st_uid == 0 and stat.S_IMODE(key.stat().st_mode) == 0o600, "TLS private key mode/owner"
        )

    check("runtime/config not service-writable; data writable; key root-only", ownership)

    def sensor():
        # Service liveness alone is not capture success; read the durable sensor object without Store migrations.
        as_service(
            "-c",
            "import sqlite3,json,time; c=sqlite3.connect('file:/var/lib/netshield/netshield.db?mode=ro',uri=True); "
            "rows=[json.loads(r[0]) for r in c.execute('SELECT body FROM v2_sensors')]; "
            "assert any(r.get('id')=="
            + repr(plan["sensor"])
            + " and r.get('interface')=="
            + repr(plan["capture"])
            + " and r.get('capture_state')=='running' and time.time()-r.get('capture_heartbeat',0)<15 for r in rows), 'No fresh running capture heartbeat'",
        )

    check("fresh running sensor heartbeat", sensor)
    if plan["response"]:

        def helper():
            import pwd

            info = Path("/run/netshield/response.sock").stat()
            account = pwd.getpwnam("netshield")
            require(
                stat.S_ISSOCK(info.st_mode)
                and info.st_uid == 0
                and info.st_gid == account.pw_gid
                and stat.S_IMODE(info.st_mode) == 0o660,
                "Unexpected socket owner/type/mode",
            )
            secure_root("/run/netshield")
            as_service(
                "-c",
                "from netshield.response import HelperClient; print(HelperClient('/run/netshield/response.sock').request('list'))",
            )
            require(check_existing_table(RUNTIME), "Owned response table missing")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect("/run/netshield/response.sock")
                client.sendall(b'{"operation":"list","target":"","ttl":0}\n')
                require(bool(json.loads(client.recv(65536)).get("error")), "Root peer unexpectedly accepted")

        check("helper socket / permitted service peer / denied root / strict owned nft schema", helper)
    print("WARN External allowed-client access and denied-client ACL require separate operator checks.")
    print("WARN No attacks, blocks or forwarding/visibility tests were run by this installer.")
    print(f"Verification: {len(failures)} failure(s).")
    return not failures


def install(args, plan, ledger, version, discovered):
    if args.non_interactive and not args.skip_operator and not ledger.state.get("operator_prompt_done"):
        raise ValueError("Non-interactive bootstrap requires --skip-operator; passwords never use flags")
    if bool(args.cert) != bool(args.key):
        raise ValueError("Supply --cert and --key together")
    listener_preflight(plan, ledger)
    if args.non_interactive:
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    # Ensure apt cannot start a newly installed global nginx/default listener.
    # Existing policy-rc.d is respected. A temporary policy is removed only if still ours.
    apt_policy = Path("/usr/sbin/policy-rc.d")
    temporary_policy = b"#!/bin/sh\n# NetShield temporary dependency-install policy\nexit 101\n"
    installed_policy = not (apt_policy.exists() or apt_policy.is_symlink())
    if installed_policy:
        with apt_policy.open("xb") as output:
            output.write(temporary_policy)
        os.chmod(apt_policy, 0o755)
    try:
        run(["apt-get", "update"], False)
        python = choose_python(args, version)
        run(
            [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "nginx",
                "openssl",
                "nftables",
                "iproute2",
                "ca-certificates",
            ],
            False,
        )
    finally:
        if installed_policy:
            if apt_policy.is_symlink() or apt_policy.read_bytes() != temporary_policy:
                raise ValueError("Temporary apt startup policy changed; inspect it manually")
            apt_policy.unlink()
    print(run(["nft", "--version"]).strip())
    account = check_account()
    if account is None:
        run(
            [
                "useradd",
                "--system",
                "--user-group",
                "--home-dir",
                "/var/lib/netshield",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "netshield",
            ]
        )
        account = check_account()
    if not STATE.parent.exists():
        STATE.parent.mkdir(mode=0o750)
        os.chown(STATE.parent, 0, account.pw_gid)
        ledger.state["directories"].append(str(STATE.parent))
        ledger.save()
    ensure_directory(STATE.parent, ledger, gid=account.pw_gid)
    ensure_directory("/opt/netshield", ledger, mode=0o755)
    ensure_directory("/var/lib/netshield", ledger, account.pw_uid, account.pw_gid, 0o700)
    ensure_directory("/etc/netshield/tls", ledger, mode=0o700)
    venv = build_runtime(python, ledger)
    # Inspect any existing table before helper startup; even observe-only never adopts it.
    check_existing_table(venv / "bin/python")
    protected = protections(plan, *discovered)
    config, policy = configurations(plan, protected, account.pw_uid, account.pw_gid)
    if ledger.state.get("plan"):
        preserved = json.loads(Path("/etc/netshield/config.json").read_text())
        # New local infrastructure must not silently weaken the preserved protections.
        if not set(protected) <= set(preserved["protected_networks"]):
            raise ValueError(
                "Infrastructure changed; review application AND helper protection policy before rerun"
            )
    else:
        ledger.write(
            "/etc/netshield/config.json",
            (json.dumps(config, indent=2) + "\n").encode(),
            0o640,
            account.pw_gid,
        )
        ledger.write(
            "/etc/netshield/helper-policy.json",
            (json.dumps(policy, indent=2) + "\n").encode(),
            0o640,
            account.pw_gid,
        )
    certificate(args, plan, ledger)
    ledger.write("/etc/netshield/nginx.conf", nginx_config(plan).encode(), 0o644)
    for suffix in UNITS:
        name = "netshield-" + suffix
        ledger.write(Path("/etc/systemd/system") / name, (ROOT / "deploy" / name).read_bytes(), 0o644)
    # nginx -t requires the configured PID parent even before first unit startup.
    # Use systemd's RuntimeDirectory preparation, not foreign /run directory adoption.
    run(["systemctl", "daemon-reload"])
    ledger.state["runtime_directories_managed"] = True
    ledger.save()
    run(
        [
            "systemd-run",
            "--quiet",
            "--wait",
            "--collect",
            "--unit=netshield-proxy-config-check",
            "--property=RuntimeDirectory=netshield-proxy",
            "--property=RuntimeDirectoryMode=0750",
            "nginx",
            "-t",
            "-c",
            "/etc/netshield/nginx.conf",
        ]
    )
    for suffix in (
        "proxy.service",
        "capture.service",
        "web.service",
        "maintenance.timer",
        "maintenance.service",
        "helper.service",
    ):
        run(["systemctl", "stop", "netshield-" + suffix])
    switch_runtime(venv, ledger)
    ledger.state["plan"] = plan
    ledger.save()
    as_service("-m", "netshield", "--config", "/etc/netshield/config.json", "init")
    if not args.skip_operator and not ledger.state.get("operator_prompt_done"):
        username = input("Initial admin username (blank to skip): ").strip()
        if username:
            run(
                [
                    "runuser",
                    "-u",
                    "netshield",
                    "--",
                    RUNTIME,
                    "-I",
                    "-m",
                    "netshield",
                    "--config",
                    "/etc/netshield/config.json",
                    "operator-add",
                    username,
                ],
                False,
            )
        ledger.state["operator_prompt_done"] = True
        ledger.save()
    for suffix in ("web.service", "capture.service", "maintenance.timer", "proxy.service"):
        run(["systemctl", "enable", "--now", "netshield-" + suffix])
    if plan["response"]:
        run(["systemctl", "enable", "--now", "netshield-helper.service"])
    else:
        run(["systemctl", "disable", "netshield-helper.service"])
    time.sleep(2)
    if not verify(ledger):
        raise ValueError(
            "Installation verification failed; inspect journalctl and preserved ledger. Do not claim ready."
        )
    print("Installed: https://" + (plan["hostname"] or plan["management"]))
    print(
        "Data/operators/certificate preserved. Observe-only."
        if not plan["response"]
        else "Manual helper explicitly enabled; automatic response remains unsupported."
    )
    print("Self-signed TLS requires deliberate client trust; no default login exists.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture-interface", "management-ip", "sensor-id", "hostname", "python", "cert", "key"):
        parser.add_argument("--" + name)
    for name in ("management-client", "response-network"):
        parser.add_argument("--" + name, action="append")
    parser.add_argument("--enable-response", action="store_true", default=None)
    for name in ("non-interactive", "skip-operator", "verify-only", "dry-run", "allow-deadsnakes"):
        parser.add_argument("--" + name, action="store_true")
    args = parser.parse_args()
    if args.verify_only and args.dry_run:
        raise ValueError("Choose verify-only OR dry-run")
    version = platform_preflight()
    ledger = ManagedFiles()
    resources_preflight(ledger)
    check_account()
    if args.verify_only:
        if not ledger.state.get("plan"):
            raise ValueError("No managed installation to verify")
        return 0 if verify(ledger) else 1
    discovered = discover()
    plan = select_plan(args, ledger, discovered[0])
    print(json.dumps({"plan": plan, "protected_networks": protections(plan, *discovered)}, indent=2))
    if args.dry_run:
        print("READ-ONLY PLAN: no apt, build, account, files, certificates, services or firewall changes.")
        return 0
    install(args, plan, ledger, version, discovered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("FAIL " + str(error), file=sys.stderr)
        # Do not dump command stdout: TLS/private material is never printed.
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr[:2000], file=sys.stderr)
        raise SystemExit(1) from None
