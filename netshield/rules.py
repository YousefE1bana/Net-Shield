"""Bounded deterministic indicators. Detection is neither attribution nor impact."""

from collections import OrderedDict, deque
from dataclasses import dataclass, asdict, replace
import hashlib
import json
import math
import ipaddress
import statistics


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    threshold: float
    window: float
    unit: str
    description: str
    severity: str = "MEDIUM"
    response_eligible: bool = False
    evidence_requirement: str = "Normalized packet metadata"
    benign_causes: str = "Authorized scanning, automation or legitimate application activity"
    version: str = "2.0.0"
    attack: str = ""
    mapping_rationale: str = ""
    confidence: str = "indicator"
    enabled: bool = True

    def record(self):
        return {
            **asdict(self),
            "rule_id": self.id,
            "enabled": self.enabled,
            "origin_eligibility": ["capture", "service_event", "replay", "isolated_lab"],
            "mode": "observe",
            "scope": "sensor + interface/VLAN + origin/run + source/target/service",
            "reference": "https://attack.mitre.org/techniques/" + self.attack.replace(".", "/") + "/"
            if self.attack
            else None,
            "mapping_review": "2026-10-04" if self.attack else None,
        }


RULES = [
    Rule(
        "NS-RECON-VERTICAL",
        "Vertical port scan indicator",
        "Reconnaissance",
        15,
        30,
        "distinct ports",
        "Initial SYNs from one source to distinct ports on one destination.",
        "HIGH",
        True,
        attack="T1046",
        mapping_rationale="Network service probing; legitimate scanners may match.",
    ),
    Rule(
        "NS-RECON-HORIZONTAL",
        "Horizontal service scan indicator",
        "Reconnaissance",
        10,
        30,
        "distinct hosts",
        "One source probes one service across distinct destinations.",
        "HIGH",
        True,
        attack="T1046",
        mapping_rationale="Service probing across hosts; no compromise inference.",
    ),
    Rule(
        "NS-RECON-SWEEP",
        "Host discovery sweep indicator",
        "Reconnaissance",
        10,
        30,
        "distinct hosts",
        "ICMP echo requests to many destinations.",
    ),
    Rule(
        "NS-RECON-ENUM",
        "Service enumeration pattern",
        "Reconnaissance",
        10,
        60,
        "distinct ports",
        "Repeated initial connections to multiple service ports; service identity unknown.",
    ),
    Rule(
        "NS-RATE-SYN",
        "SYN rate anomaly",
        "Availability",
        100,
        10,
        "initial SYNs/window",
        "Target-aggregated initial SYN count with source attribution uncertainty.",
        "HIGH",
    ),
    Rule(
        "NS-RATE-UDP",
        "UDP surge indicator",
        "Availability",
        200,
        10,
        "packets/window",
        "Target/service-aggregated UDP packet count.",
    ),
    Rule(
        "NS-RATE-ICMP",
        "ICMP surge indicator",
        "Availability",
        50,
        10,
        "packets/window",
        "Target-aggregated ICMP packet burst; impact not measured.",
    ),
    Rule(
        "NS-RATE-HTTP",
        "HTTP request surge",
        "Availability",
        50,
        10,
        "complete requests/window",
        "Complete one-packet plaintext requests or trusted HTTP service events; no HTTPS guessing.",
        evidence_requirement="Complete observable HTTP request or trusted request event",
    ),
    Rule(
        "NS-CONN-SSH",
        "Repeated SSH connection attempts",
        "Connections",
        8,
        60,
        "initial SYNs/window",
        "Connections to port 22, not authentication outcomes.",
    ),
    Rule(
        "NS-AUTH-SSH",
        "Repeated failed SSH authentication",
        "Authentication",
        5,
        60,
        "failed outcomes/window",
        "Trusted failed authentication events; credentials never retained.",
        "HIGH",
        True,
        "Trusted sshd failed-auth outcome",
        attack="T1110.001",
        mapping_rationale="Repeated failed password-authentication outcomes; guessing indicator.",
    ),
    Rule(
        "NS-AUTH-WEB",
        "Repeated failed web authentication",
        "Authentication",
        10,
        60,
        "failed outcomes/window",
        "Trusted application failed-login events.",
        "HIGH",
        True,
        "Trusted application authentication outcome",
        attack="T1110.001",
        mapping_rationale="Failed application login sequence; no confirmed credential access.",
    ),
    Rule(
        "NS-L2-ARP-CONFLICT",
        "ARP binding conflict",
        "Layer 2",
        2,
        300,
        "competing MAC claims",
        "Competing IP-to-MAC claims within the same interface/VLAN and recent baseline.",
        "MEDIUM",
        False,
        benign_causes="DHCP reassignment, VRRP/failover, deliberate network maintenance",
        attack="T1557.002",
        mapping_rationale="ARP binding anomaly relevant to poisoning; does not establish interception.",
    ),
    Rule(
        "NS-DNS-RATE",
        "DNS query-rate anomaly",
        "DNS",
        40,
        10,
        "queries/window",
        "Observed DNS query burst per source.",
    ),
    Rule(
        "NS-DNS-LONG",
        "Long DNS query indicator",
        "DNS",
        100,
        60,
        "name characters",
        "Unusually long observable DNS name; no exfiltration proof.",
    ),
    Rule(
        "NS-DNS-ENTROPY",
        "Tunneling-like DNS label indicator",
        "DNS",
        4,
        60,
        "Shannon bits/character",
        "First label length at least 32 and entropy at least threshold.",
    ),
    Rule(
        "NS-DNS-SUBDOMAINS",
        "Distinct DNS subdomain burst",
        "DNS",
        20,
        60,
        "distinct query hashes",
        "Many distinct names under the same observed last-two-label parent; public suffix not inferred.",
    ),
    Rule(
        "NS-DNS-NEW-PARENT",
        "Repeated newly observed DNS parent",
        "DNS",
        10,
        60,
        "queries/window",
        "Repeated queries to a parent first seen in this process/run; persistence coverage limited.",
        "LOW",
    ),
    Rule(
        "NS-BEHAVIOR-BEACON",
        "Periodic outbound beaconing indicator",
        "Behavior",
        8,
        3600,
        "connection observations",
        "At least eight outbound initial connections; mean interval >=2s, coefficient of variation <=0.10. Scheduled automation may match.",
    ),
    Rule(
        "NS-EGRESS-VOLUME",
        "Large outbound transfer indicator",
        "Egress",
        1048576,
        60,
        "observed bytes/window",
        "Internal source to external destination exceeds configured fixed byte budget; no learned anomaly score.",
    ),
    Rule(
        "NS-EGRESS-NEW",
        "New external destination observation",
        "Egress",
        1,
        3600,
        "first connection",
        "First external destination in bounded process/run state. Observation, not maliciousness.",
        "LOW",
    ),
    Rule(
        "NS-EGRESS-SERVICE",
        "Unexpected outbound service indicator",
        "Egress",
        1,
        60,
        "connection",
        "External service outside configured approved outbound ports.",
    ),
    Rule(
        "NS-EGRESS-FANOUT",
        "Rapid destination fan-out",
        "Egress",
        20,
        60,
        "distinct external hosts",
        "Internal source opens connections to many external destinations.",
    ),
    Rule(
        "NS-LATERAL-FANOUT",
        "Internal lateral-movement-style fan-out",
        "Lateral indicators",
        10,
        60,
        "distinct internal hosts",
        "One internal source probes SSH/SMB/RDP across internal hosts; lateral movement not confirmed.",
    ),
    Rule(
        "NS-LATERAL-SERVICE",
        "Repeated internal administration connections",
        "Lateral indicators",
        12,
        60,
        "initial connections/window",
        "Repeated internal SSH/SMB/RDP initial connections.",
    ),
    Rule(
        "NS-OPS-FAILURE",
        "Operational coverage failure",
        "Operations",
        1,
        60,
        "failure event",
        "Trusted local sensor/writer/database/helper/queue failure or stopped/stale component.",
        "HIGH",
        False,
        "Trusted health event",
    ),
]
CATALOGUE = {r.id: r for r in RULES}


def configured(overrides=None):
    overrides = overrides or {}
    if not isinstance(overrides, dict) or set(overrides) - CATALOGUE.keys():
        raise ValueError("Unknown rule configuration")
    result = {}
    for rule in RULES:
        values = overrides.get(rule.id, {})
        if not isinstance(values, dict) or set(values) - {"threshold", "window", "enabled"}:
            raise ValueError("Only threshold, window and enabled are configurable")
        if "enabled" in values and type(values["enabled"]) is not bool:
            raise ValueError("Rule enabled must be boolean")
        for name in ("threshold", "window"):
            if name in values and (type(values[name]) not in (int, float) or not math.isfinite(values[name])):
                raise ValueError("Rule parameters must be finite numbers")
        window = values.get("window", rule.window)
        threshold = values.get("threshold", rule.threshold)
        maximum = (
            16 * 1024 * 1024 if rule.id == "NS-EGRESS-VOLUME" else 8 if rule.id == "NS-DNS-ENTROPY" else 512
        )
        minimum = 2 if rule.id == "NS-L2-ARP-CONFLICT" else 3 if rule.id == "NS-BEHAVIOR-BEACON" else 1
        if not 1 <= window <= 86400 or not minimum <= threshold <= maximum:
            raise ValueError("Rule window or threshold outside supported bounds")
        if rule.id != "NS-DNS-ENTROPY" and threshold != int(threshold):
            raise ValueError("Count and byte thresholds must be whole numbers")
        if (
            rule.id in ("NS-EGRESS-NEW", "NS-EGRESS-SERVICE", "NS-OPS-FAILURE")
            and threshold != rule.threshold
        ):
            raise ValueError("This indicator has a fixed semantic threshold")
        version = (
            rule.version + "+" + hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:8]
            if values
            else rule.version
        )
        result[rule.id] = replace(rule, **values, version=version)
    return result


class RuleEngine:
    def __init__(self, settings, overrides=None):
        self.settings = settings
        self.catalogue = configured(overrides)
        self.states = OrderedDict()
        self.seen_syn = OrderedDict()
        self.dns_first_seen = OrderedDict()
        self.evictions = self.window_truncations = 0
        self.internal = [ipaddress.ip_network(x) for x in settings.internal_networks]
        self.approved_outbound = set(settings.approved_outbound_ports)

    def inside(self, address):
        return bool(address) and any(ipaddress.ip_address(address) in n for n in self.internal)

    def window(self, rule_id, scope, event, value):
        rule = self.catalogue[rule_id]
        key = (
            event.origin,
            event.run_id,
            event.sensor_id,
            event.interface,
            event.metadata.get("vlan"),
            rule_id,
            *scope,
        )
        values = self.states.pop(key, deque())
        # In-order event-time semantics; late observations retained as evidence but
        # excluded from windows by Pipeline. Empty abandoned keys are evicted.
        while values and values[0][0] < event.event_time - rule.window:
            values.popleft()
        if len(values) >= 512:
            values.popleft()
            self.window_truncations += 1
        values.append((event.event_time, value))
        self.states[key] = values
        while len(self.states) > self.settings.state_capacity:
            self.states.popitem(last=False)
            self.evictions += 1
        return values

    def evaluate(self, event):
        findings = []
        src, dst, port = event.source_ip, event.target_ip, event.target_port

        def emit(rule_id, observed, **evidence):
            rule = self.catalogue[rule_id]
            if not rule.enabled:
                return
            findings.append(
                {
                    "rule": rule,
                    "evidence": {
                        "observed": observed,
                        "threshold": rule.threshold,
                        "window_seconds": rule.window,
                        "unit": rule.unit,
                        **evidence,
                    },
                }
            )

        def count(rule_id, scope, value=1, distinct=False, byte_sum=False):
            values = self.window(rule_id, scope, event, value)
            observed = (
                len({v for _, v in values})
                if distinct
                else sum(v for _, v in values)
                if byte_sum
                else len(values)
            )
            if observed >= self.catalogue[rule_id].threshold:
                emit(
                    rule_id,
                    observed,
                    samples=[v for _, v in list(values)[-16:]],
                    source_attribution="Packet addresses may be spoofed"
                    if event.kind == "packet"
                    else "Trusted local service attribution",
                )

        flags = event.metadata.get("tcp_flags", 0)
        initial = event.protocol == "TCP" and flags & 2 and not flags & 16
        if initial:
            fingerprint = (
                event.origin,
                event.run_id,
                event.sensor_id,
                event.interface,
                event.metadata.get("vlan"),
                src,
                dst,
                event.source_port,
                port,
                event.metadata.get("tcp_sequence"),
            )
            previous = self.seen_syn.pop(fingerprint, None)
            self.seen_syn[fingerprint] = event.event_time
            while len(self.seen_syn) > self.settings.state_capacity:
                self.seen_syn.popitem(last=False)
            if previous is not None and event.event_time - previous <= 3:
                return []
            count("NS-RECON-VERTICAL", (src, dst), port, distinct=True)
            count("NS-RECON-HORIZONTAL", (src, port), dst, distinct=True)
            count("NS-RECON-ENUM", (src, dst), port, distinct=True)
            count("NS-RATE-SYN", (dst, port))
            if port == 22:
                count("NS-CONN-SSH", (src, dst, port))
            if self.inside(src) and not self.inside(dst):
                new = self.window("NS-EGRESS-NEW", (src, dst), event, 1)
                if len(new) == 1:
                    emit("NS-EGRESS-NEW", 1, baseline="First observed in bounded process/run memory")
                if port not in self.approved_outbound:
                    emit("NS-EGRESS-SERVICE", port, approved_ports=sorted(self.approved_outbound))
                count("NS-EGRESS-FANOUT", (src,), dst, distinct=True)
                timings = self.window("NS-BEHAVIOR-BEACON", (src, dst, port), event, event.event_time)
                if len(timings) >= self.catalogue["NS-BEHAVIOR-BEACON"].threshold:
                    intervals = [b[0] - a[0] for a, b in zip(timings, list(timings)[1:])]
                    mean = statistics.mean(intervals)
                    jitter = statistics.pstdev(intervals) / mean if mean else 1
                    if mean >= 2 and jitter <= 0.1:
                        emit(
                            "NS-BEHAVIOR-BEACON",
                            len(timings),
                            mean_interval=mean,
                            median_interval=statistics.median(intervals),
                            jitter_coefficient=jitter,
                            intervals=intervals[-32:],
                        )
            if self.inside(src) and self.inside(dst) and port in (22, 445, 3389):
                count("NS-LATERAL-FANOUT", (src,), dst, distinct=True)
                count("NS-LATERAL-SERVICE", (src, dst, port))
        if event.protocol in ("ICMP", "ICMPV6"):
            count("NS-RATE-ICMP", (dst,))
            if event.metadata.get("echo_request"):
                count("NS-RECON-SWEEP", (src,), dst, distinct=True)
        if event.protocol == "UDP":
            count("NS-RATE-UDP", (dst, port))
        if event.metadata.get("complete_http_requests") or event.kind == "http_request":
            count("NS-RATE-HTTP", (dst, port))
        if event.kind in ("ssh_auth", "web_auth") and event.metadata["outcome"] == "failure":
            count("NS-AUTH-SSH" if event.kind == "ssh_auth" else "NS-AUTH-WEB", (src, dst, port))
        if event.protocol == "ARP" and event.metadata.get("arp_operation") == 2:
            mac = event.metadata["claimed_mac"]
            values = self.window("NS-L2-ARP-CONFLICT", (src,), event, mac)
            macs = sorted({v for _, v in values})
            if len(macs) >= self.catalogue["NS-L2-ARP-CONFLICT"].threshold:
                emit(
                    "NS-L2-ARP-CONFLICT",
                    len(macs),
                    claimed_ip=src,
                    competing_macs=macs,
                    interpretation="Possible spoofing or legitimate rebinding; no MITM proof",
                )
        if event.metadata.get("dns_query"):
            parent = event.metadata["dns_parent"]
            count("NS-DNS-RATE", (src,))
            count("NS-DNS-SUBDOMAINS", (src, parent), event.metadata["dns_query_hash"], distinct=True)
            baseline_key = (
                event.origin,
                event.run_id,
                event.sensor_id,
                event.interface,
                event.metadata.get("vlan"),
                src,
                parent,
            )
            first = self.dns_first_seen.pop(baseline_key, event.event_time)
            self.dns_first_seen[baseline_key] = first
            while len(self.dns_first_seen) > self.settings.state_capacity:
                self.dns_first_seen.popitem(last=False)
                self.evictions += 1
            if event.event_time - first <= self.catalogue["NS-DNS-NEW-PARENT"].window:
                count("NS-DNS-NEW-PARENT", (src, parent))
            if event.metadata["dns_length"] >= self.catalogue["NS-DNS-LONG"].threshold:
                emit("NS-DNS-LONG", event.metadata["dns_length"], parent=parent)
            if (
                event.metadata["dns_label_length"] >= 32
                and event.metadata["dns_entropy"] >= self.catalogue["NS-DNS-ENTROPY"].threshold
            ):
                emit(
                    "NS-DNS-ENTROPY",
                    event.metadata["dns_entropy"],
                    label_length=event.metadata["dns_label_length"],
                    parent=parent,
                )
        if self.inside(src) and dst and not self.inside(dst) and event.kind == "packet":
            count("NS-EGRESS-VOLUME", (src, dst), event.length, byte_sum=True)
        if event.kind == "operational" and event.metadata.get("state") in (
            "failed",
            "stopped",
            "stale",
            "overflow",
        ):
            emit("NS-OPS-FAILURE", 1, **event.metadata)
        return findings
