"""Trusted ingress normalizers. No payload/credentials persist in events."""

from dataclasses import dataclass, field, asdict
from enum import StrEnum
import hashlib
import ipaddress
import math
import time
from collections import Counter
from scapy.all import ARP, DNS, DNSQR, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.inet6 import IPv6ExtHdrFragment
from .store import uid


class Origin(StrEnum):
    CAPTURE = "capture"
    SERVICE_EVENT = "service_event"
    REPLAY = "replay"
    ISOLATED_LAB = "isolated_lab"


@dataclass(frozen=True)
class Event:
    origin: str
    sensor_id: str
    interface: str
    run_id: str
    event_time: float
    source_ip: str = ""
    target_ip: str = ""
    source_port: int = 0
    target_port: int = 0
    protocol: str = ""
    kind: str = "packet"
    length: int = 0
    metadata: dict = field(default_factory=dict)
    id: str = field(default_factory=uid)
    ingest_time: float = field(default_factory=time.time)

    def record(self):
        return asdict(self)


def host(value, empty=False):
    if empty and value in (None, ""):
        return ""
    return str(ipaddress.ip_address(value))


def timestamp(value):
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError("Invalid event timestamp")
    return value


def normalize_packet(packet, origin, sensor_id, interface, run_id=""):
    if not isinstance(origin, Origin):
        raise ValueError("Origin must be assigned by trusted ingress")
    meta = {"vlan": int(packet[Dot1Q].vlan) if Dot1Q in packet else None}
    src = dst = protocol = ""
    sport = dport = 0
    if Ether in packet:
        meta.update(source_mac=str(packet[Ether].src), target_mac=str(packet[Ether].dst))
    if ARP in packet:
        arp = packet[ARP]
        src, dst, protocol = host(arp.psrc), host(arp.pdst), "ARP"
        meta.update(arp_operation=int(arp.op), claimed_mac=str(arp.hwsrc).lower())
    elif IP in packet or IPv6 in packet:
        layer = packet[IP] if IP in packet else packet[IPv6]
        src, dst = host(layer.src), host(layer.dst)
        meta["ip_version"] = 4 if IP in packet else 6
        fragmented = (
            IP in packet and (packet[IP].frag != 0 or bool(int(packet[IP].flags) & 1))
        ) or IPv6ExtHdrFragment in packet
        meta["fragmented"] = fragmented
        if fragmented:
            protocol = "FRAGMENT"
        elif TCP in packet:
            tcp = packet[TCP]
            sport, dport, protocol = int(tcp.sport), int(tcp.dport), "TCP"
            meta.update(tcp_flags=int(tcp.flags), tcp_sequence=int(tcp.seq), tcp_ack=int(tcp.ack))
            # Whole request only, fitting in one packet; no stream/decryption claim.
            if Raw in packet and dport in (80, 8080):
                payload = bytes(packet[Raw].load)[:8192]
                first, _, remainder = payload.partition(b"\r\n")
                if (
                    first.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "))
                    and b" HTTP/1." in first
                    and b"\r\n\r\n" in payload
                ):
                    headers, content = payload.split(b"\r\n\r\n", 1)
                    lengths = [
                        h.split(b":", 1)[1].strip()
                        for h in headers.split(b"\r\n")
                        if h.lower().startswith(b"content-length:")
                    ]
                    chunked = b"transfer-encoding:" in headers.lower()
                    if not chunked and (
                        not lengths
                        or (len(lengths) == 1 and lengths[0].isdigit() and int(lengths[0]) == len(content))
                    ):
                        meta["complete_http_requests"] = 1
        elif UDP in packet:
            sport, dport, protocol = int(packet[UDP].sport), int(packet[UDP].dport), "UDP"
        elif ICMP in packet or ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
            protocol = "ICMP" if ICMP in packet else "ICMPV6"
            meta["echo_request"] = (ICMP in packet and packet[ICMP].type == 8) or ICMPv6EchoRequest in packet
    else:
        protocol = "OTHER"
    if protocol == "UDP" and dport == 53 and DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
        name = bytes(packet[DNSQR].qname).decode("ascii", errors="replace").rstrip(".").lower()[:255]
        label = name.split(".")[0]
        counts = Counter(label)
        entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in counts.values()) if label else 0
        meta.update(
            dns_query=True,
            dns_parent=".".join(name.split(".")[-2:]),
            dns_length=len(name),
            dns_label_length=len(label),
            dns_entropy=round(entropy, 3),
            dns_query_hash=hashlib.sha256(name.encode()).hexdigest(),
        )
    return Event(
        origin,
        sensor_id,
        interface,
        run_id,
        timestamp(packet.time),
        src,
        dst,
        sport,
        dport,
        protocol,
        length=len(packet),
        metadata=meta,
    )


def normalize_service(value, origin, sensor_id, run_id=""):
    if not isinstance(origin, Origin):
        raise ValueError("Origin must be assigned by trusted ingress")
    allowed = {
        "kind",
        "event_time",
        "source_ip",
        "target_ip",
        "target_port",
        "outcome",
        "component",
        "state",
        "error_code",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Service contract rejects caller provenance and unknown fields")
    kind = value.get("kind")
    if kind not in ("ssh_auth", "web_auth", "http_request", "operational"):
        raise ValueError("Unsupported service event")
    outcome = value.get("outcome")
    if kind in ("ssh_auth", "web_auth") and outcome not in ("failure", "success"):
        raise ValueError("Authentication outcome required")
    port = value.get("target_port", 22 if kind == "ssh_auth" else 8080)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Invalid service port")
    meta = {k: value[k] for k in ("outcome", "component", "state", "error_code") if k in value}
    if any(not isinstance(v, str) or len(v) > 80 for v in meta.values()):
        raise ValueError("Service metadata outside bounds")
    return Event(
        origin,
        sensor_id,
        "trusted-local-service",
        run_id,
        timestamp(value.get("event_time", time.time())),
        host(value.get("source_ip"), empty=True),
        host(value.get("target_ip"), empty=True),
        target_port=port,
        protocol="SERVICE",
        kind=kind,
        metadata=meta,
    )
