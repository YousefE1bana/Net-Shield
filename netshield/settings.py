"""Typed local configuration. Privileged capabilities are never web settings."""

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import json
import os
import re


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("NETSHIELD_DATA", "data")))
    database: Path | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    secure_cookie: bool = False
    trusted_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    interface: str = ""
    sensor_id: str = "local"
    internal_networks: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8")
    approved_outbound_ports: tuple[int, ...] = (53, 80, 123, 443)
    response_enabled: bool = False
    auto_response: bool = False
    helper_socket: str = "/run/netshield/response.sock"
    protected_networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10")
    response_networks: tuple[str, ...] = ()
    queue_capacity: int = 2048
    state_capacity: int = 4096
    event_retention_days: int = 7
    evidence_retention_days: int = 90
    flow_idle_seconds: int = 60

    def __post_init__(self):
        for key in ("secure_cookie", "response_enabled", "auto_response"):
            if type(getattr(self, key)) is not bool:
                raise ValueError(key + " must be boolean")
        for key in (
            "port",
            "queue_capacity",
            "state_capacity",
            "event_retention_days",
            "evidence_retention_days",
            "flow_idle_seconds",
        ):
            if type(getattr(self, key)) is not int:
                raise ValueError(key + " must be an integer")
        if (
            not isinstance(self.interface, str)
            or len(self.interface) > 64
            or not isinstance(self.sensor_id, str)
            or not 1 <= len(self.sensor_id) <= 64
        ):
            raise ValueError("Invalid interface or sensor identifier")
        if self.interface and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", self.interface):
            raise ValueError("Capture requires a literal Linux interface name")
        object.__setattr__(self, "data_dir", Path(self.data_dir).resolve())
        object.__setattr__(
            self,
            "database",
            Path(self.database).resolve() if self.database else self.data_dir / "netshield.db",
        )
        if self.auto_response:
            raise ValueError("Automatic response is not supported; use verified manual decisions")
        if not ipaddress.ip_address(self.host).is_loopback:
            raise ValueError(
                "Management bind must be loopback; remote access requires an explicit TLS reverse proxy"
            )
        if (
            not 1 <= self.port <= 65535
            or not 16 <= self.queue_capacity <= 65536
            or not 64 <= self.state_capacity <= 65536
        ):
            raise ValueError("Configuration outside supported bounds")
        if not 1 <= self.event_retention_days <= 365 or not 7 <= self.evidence_retention_days <= 3650:
            raise ValueError("Retention outside supported bounds")
        if not 5 <= self.flow_idle_seconds <= 3600:
            raise ValueError("Flow idle interval must be 5–3600 seconds")
        for value in (*self.internal_networks, *self.protected_networks, *self.response_networks):
            ipaddress.ip_network(value)
        if (
            not isinstance(self.approved_outbound_ports, (tuple, list))
            or not 1 <= len(self.approved_outbound_ports) <= 64
        ):
            raise ValueError("Approved outbound ports require 1–64 literal ports")
        if any(type(p) is not int or not 1 <= p <= 65535 for p in self.approved_outbound_ports):
            raise ValueError("Approved outbound ports must be integers in 1–65535")
        object.__setattr__(self, "approved_outbound_ports", tuple(self.approved_outbound_ports))

    @classmethod
    def load(cls, path=None):
        values = json.loads(Path(path).read_text()) if path else {}
        if not isinstance(values, dict):
            raise ValueError("Configuration must be an object")
        unknown = set(values) - cls.__dataclass_fields__.keys()
        if unknown:
            raise ValueError("Unknown configuration keys: " + ", ".join(sorted(unknown)))
        for key in ("trusted_hosts", "internal_networks", "protected_networks", "response_networks"):
            if key in values:
                if not isinstance(values[key], list) or any(not isinstance(x, str) for x in values[key]):
                    raise ValueError(key + " must be an array of strings")
                values[key] = tuple(values[key])
        return cls(**values)
