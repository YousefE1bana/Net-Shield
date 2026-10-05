"""Optional Linux-only root helper; fixed owned nftables objects, never a shell.

Local root owns its policy/config. The web process cannot change helper scope.
Timeout sets keep finite kernel expiry even when management is unavailable.
"""

import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import stat
import struct
import subprocess

TABLE = "netshield_v2"
MARKER = "NetShield V2 owned response boundary"


def execute(arguments, input=None):
    result = subprocess.run(
        ["/usr/sbin/nft", *arguments], input=input, text=True, capture_output=True, timeout=5, check=False
    )
    if result.returncode:
        raise OSError("nftables operation failed")
    return json.loads(result.stdout) if "-j" in arguments else result.stdout


def table_marker(text):
    """Old nft JSON omits table comments. Accept only the same table's marker.

    Tokenize quoted strings before braces: a nested object's comment, quoted
    braces, a substring or a second rendered table cannot establish ownership.
    JSON still governs the complete schema; text supplies only the missing field.
    """
    if not isinstance(text, str):
        return False
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[{};]|[^\s{};"]+', text)
    if tokens[:4] != ["table", "inet", TABLE, "{"]:
        return False
    depth, markers = 1, []
    for index in range(4, len(tokens)):
        token = tokens[index]
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                return index == len(tokens) - 1 and markers == [MARKER]
            if depth < 0:
                return False
        elif token == "comment" and depth == 1:
            try:
                markers.append(json.loads(tokens[index + 1]))
            except (IndexError, ValueError):
                return False
    return False


class NftBoundary:
    def __init__(self, allowed, protected, runner=execute):
        self.allowed = tuple(ipaddress.ip_network(n) for n in allowed)
        self.protected = tuple(ipaddress.ip_network(n) for n in protected)
        if not self.allowed or not self.protected:
            raise ValueError("Helper requires explicit response scope and infrastructure protection")
        self.runner = runner

    def target(self, value, enforce_policy=True):
        if not isinstance(value, str):
            raise ValueError("Target must be a literal IP string")
        address = ipaddress.ip_address(value)
        if enforce_policy and (
            address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local
        ):
            raise ValueError("Special-use target denied")
        if enforce_policy and (
            any(address in n for n in self.protected) or not any(address in n for n in self.allowed)
        ):
            raise ValueError("Helper policy denies target")
        return str(address), "blocked4" if address.version == 4 else "blocked6"

    def initialize(self):
        tables = self.runner(["-j", "list", "tables"]).get("nftables", [])
        if any(x.get("table", {}).get("name") == TABLE for x in tables):
            self.inspect()  # Never adopt or overwrite a foreign/changed table.
            return
        script = f'create table inet {TABLE} {{ comment "{MARKER}"; }}\n'
        for name, datatype in (("blocked4", "ipv4_addr"), ("blocked6", "ipv6_addr")):
            script += (
                f"add set inet {TABLE} {name} {{ type {datatype}; flags timeout; timeout 1h; size 1024; }}\n"
            )
        for hook in ("input", "forward"):
            script += (
                f"add chain inet {TABLE} {hook} {{ type filter hook {hook} priority -10; policy accept; }}\n"
            )
            for family, name in (("ip", "blocked4"), ("ip6", "blocked6")):
                script += f"add rule inet {TABLE} {hook} {family} saddr @{name} counter drop\n"
        self.runner(["-f", "-"], script)
        self.inspect()

    def inspect(self):
        objects = self.runner(["-j", "list", "table", "inet", TABLE]).get("nftables", [])
        tables = [x["table"] for x in objects if "table" in x]
        sets = [x["set"] for x in objects if "set" in x]
        chains = [x["chain"] for x in objects if "chain" in x]
        rules = [x["rule"] for x in objects if "rule" in x]
        if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != TABLE:
            raise OSError("Foreign response table; refused")
        owned = (
            tables[0]["comment"] == MARKER
            if "comment" in tables[0]
            else table_marker(self.runner(["list", "table", "inet", TABLE]))
        )
        if not owned:
            raise OSError("Foreign response table; refused")
        if {x["name"] for x in sets} != {"blocked4", "blocked6"} or len(sets) != 2:
            raise OSError("Response sets changed; refused")
        for item in sets:
            expected = "ipv4_addr" if item["name"] == "blocked4" else "ipv6_addr"
            if item.get("type") != expected or "timeout" not in item.get("flags", []):
                raise OSError("Response set schema changed; refused")
        if len(chains) != 2 or {x["name"] for x in chains} != {"input", "forward"}:
            raise OSError("Response chains changed; refused")
        for chain in chains:
            if (
                chain.get("hook") != chain["name"]
                or chain.get("type") != "filter"
                or chain.get("policy") != "accept"
                or chain.get("prio") != -10
            ):
                raise OSError("Response hook changed; refused")
        expected_rules = {(hook, family) for hook in ("input", "forward") for family in ("ip", "ip6")}
        observed = set()
        for rule in rules:
            expr = rule.get("expr", [])
            if (
                len(expr) != 3
                or "match" not in expr[0]
                or "counter" not in expr[1]
                or expr[2] != {"drop": None}
            ):
                raise OSError("Response rule changed; refused")
            match = expr[0]["match"]
            family = match.get("left", {}).get("payload", {}).get("protocol")
            name = "blocked4" if family == "ip" else "blocked6"
            if (
                match.get("op") != "=="
                or match.get("left") != {"payload": {"protocol": family, "field": "saddr"}}
                or match.get("right") != "@" + name
            ):
                raise OSError("Response rule expression changed; refused")
            observed.add((rule.get("chain"), family))
        if observed != expected_rules or len(rules) != 4:
            raise OSError("Response rules incomplete; refused")
        targets = []
        for item in sets:
            for element in item.get("elem", []):
                timed = element.get("elem", {}) if isinstance(element, dict) else {}
                expires = timed.get("expires")
                if type(expires) not in (int, float) or not 0 <= expires <= 3600000:
                    raise OSError("Response element has no verified finite kernel expiry")
                value = element.get("elem", {}).get("val") if isinstance(element, dict) else element
                address, _ = self.target(value, False)
                targets.append(address)
        return {
            "targets": sorted(targets),
            "backend": "nftables",
            "scope": "inet/netshield_v2 input+forward source sets",
        }

    def request(self, operation, target="", ttl=0):
        if operation not in ("list", "add", "remove"):
            raise ValueError("Unsupported helper operation")
        before = self.inspect()
        if operation == "list":
            return before
        target, name = self.target(target, operation == "add")
        if operation == "add":
            if type(ttl) is not int or not 60 <= ttl <= 3600:
                raise ValueError("Invalid kernel TTL")
            if target not in before["targets"]:
                self.runner(["-f", "-"], f"add element inet {TABLE} {name} {{ {target} timeout {ttl}s }}\n")
        elif target in before["targets"]:
            self.runner(["-f", "-"], f"delete element inet {TABLE} {name} {{ {target} }}\n")
        return self.inspect()


def serve_helper(config_path):
    path = Path(config_path).resolve()
    details = path.stat()
    if os.name != "posix" or os.geteuid() != 0 or details.st_uid != 0 or details.st_mode & 0o022:
        raise ValueError("Helper requires Linux root and a root-owned non-writable policy")
    config = json.loads(path.read_text())
    if not isinstance(config, dict) or set(config) != {
        "allowed_networks",
        "protected_networks",
        "client_uid",
        "client_gid",
        "socket",
    }:
        raise ValueError("Invalid helper policy")
    if type(config["client_uid"]) is not int or config["client_uid"] <= 0:
        raise ValueError("Helper client must be an unprivileged numeric UID")
    if type(config["client_gid"]) is not int or config["client_gid"] < 0:
        raise ValueError("Invalid helper client GID")
    boundary = NftBoundary(
        config["allowed_networks"], [*config["protected_networks"], *infrastructure_networks()]
    )
    endpoint = Path(config["socket"])
    if endpoint.parent != Path("/run/netshield"):
        raise ValueError("Helper socket must be inside /run/netshield")
    endpoint.parent.mkdir(mode=0o750, exist_ok=True)
    parent = endpoint.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("Helper runtime directory must be a root-owned non-writable directory")
    os.chown(endpoint.parent, 0, config["client_gid"])
    endpoint.parent.chmod(0o750)
    if endpoint.exists() or endpoint.is_symlink():
        if not stat.S_ISSOCK(endpoint.lstat().st_mode) or endpoint.lstat().st_uid != 0:
            raise ValueError("Refusing to replace foreign socket path")
        endpoint.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(endpoint))
        os.chown(endpoint, 0, config["client_gid"])
        endpoint.chmod(0o660)
        boundary.initialize()  # Only after runtime/policy paths were validated.
        server.listen(8)
        try:
            while True:
                with server.accept()[0] as client:
                    client.settimeout(3)
                    try:
                        _, uid, _ = struct.unpack(
                            "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                        )
                        if uid != config["client_uid"]:
                            raise ValueError("Peer denied")
                        data = bytearray()
                        while b"\n" not in data and len(data) <= 4096:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            data.extend(chunk)
                        if len(data) > 4096 or b"\n" not in data:
                            raise ValueError("Invalid helper frame")
                        value = json.loads(data)
                        if not isinstance(value, dict) or set(value) != {"operation", "target", "ttl"}:
                            raise ValueError("Unsupported helper fields")
                        reply = boundary.request(**value)
                    except (ValueError, OSError, KeyError, TypeError):
                        reply = {"error": "Policy or kernel verification failed"}
                    try:
                        client.sendall(json.dumps(reply).encode() + b"\n")
                    except OSError:
                        pass  # A disconnected peer cannot stop the service.
        finally:
            endpoint.unlink(missing_ok=True)


def infrastructure_networks():
    """Always protect local addresses, discovered gateways and resolver IPs.

    Independent of browser policy. Discovery failure refuses helper startup.
    Operators additionally protect management jump hosts in root-owned policy.
    """
    addresses = set()
    for arguments in (
        ["-j", "address", "show"],
        ["-j", "route", "show", "default"],
        ["-j", "-6", "route", "show", "default"],
    ):
        result = subprocess.run(
            ["/usr/sbin/ip", *arguments], capture_output=True, text=True, timeout=5, check=True
        )
        for record in json.loads(result.stdout):
            if record.get("gateway"):
                addresses.add(record["gateway"])
            for info in record.get("addr_info", []):
                addresses.add(info["local"])
    for line in Path("/etc/resolv.conf").read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            addresses.add(parts[1])
    return [
        str(ipaddress.ip_network(str(ipaddress.ip_address(a)) + ("/128" if ":" in a else "/32")))
        for a in addresses
    ]
