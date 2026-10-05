"""Bounded, deterministic authored fixtures through the real parser and rules.

Nothing in this module opens a network socket or requests firewall authority.
Recorded packet time, not wall-clock replay speed, drives detector windows.
"""

from pathlib import Path
import hashlib
import json
import threading
import time
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP, wrpcap
from .events import Origin
from .pipeline import Pipeline
from .store import uid

BASE = 1700000000.0
SOURCE, TARGET, EXTERNAL = "10.77.0.2", "10.77.0.10", "203.0.113.20"


def scenario(name, rule, budget, category, description, service=False):
    return {
        "name": name,
        "expected_rules": [rule] if rule else [],
        "budget": budget,
        "category": category,
        "description": description,
        "service_events": service,
        "mode": "replay",
        "network_access": False,
        "response": "dry-run only",
        "duration": "Recorded event-time; accelerated offline",
        "available": True,
        "version": "1.0.0",
        "rate_cap": "Offline only; no transmission",
        "timeout_seconds": 120,
    }


SCENARIOS = {
    "port-scan": scenario(
        "Vertical port scan",
        "NS-RECON-VERTICAL",
        18,
        "Reconnaissance",
        "Distinct destination ports from an authored source.",
    ),
    "horizontal-scan": scenario(
        "Horizontal service scan",
        "NS-RECON-HORIZONTAL",
        12,
        "Reconnaissance",
        "One port across observed destinations.",
    ),
    "host-sweep": scenario(
        "ICMP host sweep", "NS-RECON-SWEEP", 12, "Reconnaissance", "Echo requests to distinct lab addresses."
    ),
    "syn-rate": scenario(
        "SYN rate test",
        "NS-RATE-SYN",
        105,
        "Availability",
        "Bounded initial SYN burst; no attack-impact claim.",
    ),
    "udp-surge": scenario(
        "UDP packet surge", "NS-RATE-UDP", 205, "Availability", "Target/service packet-rate threshold."
    ),
    "icmp-surge": scenario(
        "ICMP packet surge", "NS-RATE-ICMP", 55, "Availability", "Target-aggregated ICMP burst."
    ),
    "http-surge": scenario(
        "HTTP request surge",
        "NS-RATE-HTTP",
        55,
        "Availability",
        "Complete plaintext requests; no HTTPS inference.",
    ),
    "ssh-connections": scenario(
        "SSH connection attempts",
        "NS-CONN-SSH",
        10,
        "Connections",
        "Transport attempts do not prove authentication failure.",
    ),
    "ssh-failures": scenario(
        "SSH failed authentication",
        "NS-AUTH-SSH",
        7,
        "Authentication",
        "Authored trusted-outcome fixture; no passwords.",
        True,
    ),
    "web-failures": scenario(
        "Web failed authentication",
        "NS-AUTH-WEB",
        12,
        "Authentication",
        "Authored failed-outcome fixture.",
        True,
    ),
    "arp-conflict": scenario(
        "ARP binding conflict",
        "NS-L2-ARP-CONFLICT",
        2,
        "Layer 2",
        "Competing MAC claims; interception is not asserted.",
    ),
    "dns-rate": scenario(
        "DNS query rate", "NS-DNS-RATE", 45, "DNS", "Bounded query sequence, no external resolver."
    ),
    "dns-long": scenario(
        "Long DNS query", "NS-DNS-LONG", 1, "DNS", "Long labels under reserved .test parent."
    ),
    "dns-entropy": scenario(
        "DNS label entropy", "NS-DNS-ENTROPY", 1, "DNS", "High-entropy label; tunneling not established."
    ),
    "dns-subdomains": scenario(
        "DNS subdomain diversity", "NS-DNS-SUBDOMAINS", 22, "DNS", "Distinct query hashes under a parent."
    ),
    "dns-new-parent": scenario(
        "New DNS parent burst", "NS-DNS-NEW-PARENT", 12, "DNS", "New parent in this bounded run baseline."
    ),
    "beacon": scenario(
        "Periodic connection pattern",
        "NS-BEHAVIOR-BEACON",
        10,
        "Behavior",
        "Regular event-time intervals; no C2 attribution.",
    ),
    "egress-volume": scenario(
        "Outbound byte budget",
        "NS-EGRESS-VOLUME",
        260,
        "Egress",
        "1 MiB outbound observation budget, no exfiltration proof.",
    ),
    "egress-new": scenario(
        "New outbound destination", "NS-EGRESS-NEW", 1, "Egress", "First observed reserved external endpoint."
    ),
    "egress-service": scenario(
        "Unapproved outbound service", "NS-EGRESS-SERVICE", 1, "Egress", "Local-policy service indicator."
    ),
    "egress-fanout": scenario(
        "Outbound destination fan-out", "NS-EGRESS-FANOUT", 22, "Egress", "Many reserved external endpoints."
    ),
    "lateral-fanout": scenario(
        "Internal service fan-out",
        "NS-LATERAL-FANOUT",
        12,
        "Lateral movement indicators",
        "Internal SSH probing, no confirmed movement.",
    ),
    "lateral-service": scenario(
        "Internal service repetition",
        "NS-LATERAL-SERVICE",
        14,
        "Lateral movement indicators",
        "Repeated initial connections to an internal service.",
    ),
    "sensor-failure": scenario(
        "Operational failure event",
        "NS-OPS-FAILURE",
        1,
        "Operations",
        "Authored replay event, not a failure of the active sensor.",
        True,
    ),
    "benign": scenario(
        "Benign conversation",
        "",
        6,
        "Negative control",
        "One established internal conversation; expect zero findings.",
    ),
    "ipv6-scan": scenario(
        "IPv6 vertical scan",
        "NS-RECON-VERTICAL",
        18,
        "Reconnaissance",
        "IPv6 parser and detector validation.",
    ),
    "lateral-smb": scenario(
        "Repeated internal SMB-style connections",
        "NS-LATERAL-SERVICE",
        14,
        "Lateral movement indicators",
        "Observable port 445 connections; no Windows authentication inference.",
    ),
    "lateral-rdp": scenario(
        "Repeated internal RDP-style connections",
        "NS-LATERAL-SERVICE",
        14,
        "Lateral movement indicators",
        "Observable port 3389 connections; no remote session inference.",
    ),
    "helper-failure": scenario(
        "Response helper failure event",
        "NS-OPS-FAILURE",
        1,
        "Operations",
        "Authored local-component failure fixture; no host firewall call.",
        True,
    ),
    "writer-failure": scenario(
        "Writer failure event",
        "NS-OPS-FAILURE",
        1,
        "Operations",
        "Authored writer coverage event; active database is not damaged.",
        True,
    ),
    "benign-scanner": scenario(
        "Low-volume authorized scanner",
        "",
        8,
        "Negative control",
        "Eight distinct lab ports below reconnaissance thresholds.",
    ),
    "benign-http": scenario(
        "Legitimate HTTP burst",
        "",
        10,
        "Negative control",
        "Ten complete local requests below the configured surge threshold.",
    ),
    "benign-dns": scenario(
        "Legitimate DNS workload",
        "",
        24,
        "Negative control",
        "Multiple .test parents, each below burst thresholds.",
    ),
}


def fixtures(identity):
    if identity not in SCENARIOS:
        raise ValueError("Unknown controlled scenario")
    spec = SCENARIOS[identity]
    for index in range(spec["budget"]):
        now = BASE + index * (30 if identity == "beacon" else 0.05)
        if spec["service_events"]:
            value = {"event_time": now, "source_ip": SOURCE, "target_ip": TARGET}
            if identity in ("sensor-failure", "helper-failure", "writer-failure"):
                value.update(
                    kind="operational",
                    component="fixture-" + identity.split("-")[0],
                    state="failed",
                    error_code="ControlledReplayFailure",
                )
            else:
                value.update(kind="ssh_auth" if identity == "ssh-failures" else "web_auth", outcome="failure")
            yield value
            continue
        src, dst, port = SOURCE, TARGET, 443
        if identity in ("port-scan", "ipv6-scan", "benign-scanner"):
            port = 8000 + index
        elif identity in ("horizontal-scan", "lateral-fanout"):
            dst, port = f"10.77.0.{20 + index}", 22
        elif identity in ("ssh-connections", "lateral-service", "lateral-smb", "lateral-rdp"):
            port = 445 if identity == "lateral-smb" else 3389 if identity == "lateral-rdp" else 22
        elif identity.startswith("egress") or identity == "beacon":
            dst = f"203.0.113.{20 + index}" if identity == "egress-fanout" else EXTERNAL
            port = 4444 if identity == "egress-service" else 443
        layer = IPv6(src="fd77::2", dst="fd77::10") if identity == "ipv6-scan" else IP(src=src, dst=dst)
        packet = layer / TCP(sport=40000 + index, dport=port, flags="S", seq=100 + index)
        if identity == "benign":
            packet = (
                (IP(src=TARGET, dst=SOURCE) / TCP(sport=443, dport=40000, flags="A"))
                if index % 2
                else IP(src=SOURCE, dst=TARGET) / TCP(sport=40000, dport=443, flags="A")
            )
        elif identity in ("host-sweep", "icmp-surge"):
            packet = IP(
                src=SOURCE, dst=f"10.77.0.{20 + index}" if identity == "host-sweep" else TARGET
            ) / ICMP(type=8)
        elif identity in ("udp-surge", "egress-volume"):
            packet = (
                layer
                / UDP(sport=40000 + index, dport=443)
                / Raw(b"x" * (4096 if identity == "egress-volume" else 8))
            )
        elif identity in ("http-surge", "benign-http"):
            packet = (
                layer
                / TCP(sport=40000 + index, dport=8080, flags="PA")
                / Raw(b"GET / HTTP/1.1\r\nHost: lab.test\r\n\r\n")
            )
        elif identity == "arp-conflict":
            packet = Ether(src=f"02:00:00:00:00:0{index + 1}", dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc=TARGET, pdst=SOURCE, hwsrc=f"02:00:00:00:00:0{index + 1}"
            )
        elif identity.startswith("dns-") or identity == "benign-dns":
            name = f"n{index}.lab.test" if identity == "dns-subdomains" else "www.lab.test"
            if identity == "benign-dns":
                name = f"www.parent{index // 6}.test"
            if identity == "dns-long":
                name = "a" * 55 + "." + "b" * 55 + ".lab.test"
            elif identity == "dns-entropy":
                name = "abcdefghijklmnopqrstuvwxyz0123456789.lab.test"
            packet = layer / UDP(sport=40000 + index, dport=53) / DNS(id=index, rd=1, qd=DNSQR(qname=name))
        if Ether not in packet:
            packet = Ether(src="02:00:00:00:77:02", dst="02:00:00:00:77:10") / packet
        packet.time = now
        yield packet


class Replay:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.current = None

    def run(self, identity, actor, run_id=None):
        if identity not in SCENARIOS:
            raise ValueError("Unknown controlled scenario")
        if not self.lock.acquire(blocking=False):
            raise ValueError("One controlled replay may run at a time")
        self.cancel.clear()
        spec = SCENARIOS[identity]
        record = {
            "id": run_id or uid(),
            "scenario": identity,
            "name": spec["name"],
            "origin": "replay",
            "status": "RUNNING",
            "actor": actor,
            "started_at": time.time(),
            "expected_rules": spec["expected_rules"],
            "budget": spec["budget"],
            "processed": 0,
            "observed_rules": [],
            "response": "No live authority",
            "network_access": False,
            "scenario_version": spec["version"],
            "stage": "PRECHECK",
            "generated_count": 0,
            "detected_events": 0,
            "cleanup": "Not required: offline, no network resources created",
        }
        record["run_id"] = record["id"]
        self.current = record["id"]
        self.store.put("lab_runs", record)
        self.store.audit(actor, "replay.started", record["id"], "RUNNING", scenario=identity)
        start = time.perf_counter()
        try:
            pipeline = Pipeline(self.store, self.settings)
            record["rule_versions"] = {r.id: r.version for r in pipeline.rules.catalogue.values()}
            digest = hashlib.sha256()
            observed = set()
            for value in fixtures(identity):
                if self.cancel.is_set() or time.perf_counter() - start > 120:
                    record["status"] = "INCOMPLETE"
                    record["error"] = "Cancelled or execution time budget reached"
                    break
                digest.update(
                    json.dumps(value, sort_keys=True).encode()
                    if isinstance(value, dict)
                    else bytes(value) + str(value.time).encode()
                )
                record["generated_count"] += 1
                record["stage"] = "OBSERVE_AND_DETECT"
                result = (
                    pipeline.service(value, Origin.REPLAY, record["id"])
                    if isinstance(value, dict)
                    else pipeline.packet(value, Origin.REPLAY, record["id"], "fixture")
                )
                observed.update(x["rule_id"] for x in result["alerts"])
                record["detected_events"] += len(result["alerts"])
                record.update(
                    processed=record["processed"] + 1,
                    observed_rules=sorted(observed),
                    elapsed_seconds=time.perf_counter() - start,
                )
                if record["processed"] % 10 == 0:
                    self.store.put("lab_runs", record)
            else:
                expected = set(spec["expected_rules"])
                record["status"] = "PASS" if (expected <= observed if expected else not observed) else "FAIL"
            record["assertions"] = [
                {"rule": rule, "passed": rule in observed} for rule in spec["expected_rules"]
            ]
            if not spec["expected_rules"]:
                record["assertions"] = [{"rule": "No findings (negative control)", "passed": not observed}]
            record["coverage"] = {
                "parser_failures": pipeline.parser_failures,
                "late_events": pipeline.late_events,
                "state_evictions": pipeline.rules.evictions,
                "window_truncations": pipeline.rules.window_truncations,
            }
            record["fixture_sha256"] = digest.hexdigest()
            record["stage"] = "VERIFY"
        except Exception as error:
            record.update(status="INCOMPLETE", error=type(error).__name__)
        finally:
            record.update(finished_at=time.time(), elapsed_seconds=time.perf_counter() - start)
            record["stage"] = "COMPLETE" if record["status"] in ("PASS", "FAIL") else "INCOMPLETE"
            self.store.put("lab_runs", record)
            self.store.audit(actor, "replay.finished", record["id"], record["status"])
            self.current = None
            self.lock.release()
        return record

    def import_pcap(self, path, actor, max_packets=5000):
        path = Path(path).resolve()
        if not path.is_file() or path.stat().st_size > 20 * 1024 * 1024 or not 1 <= max_packets <= 5000:
            raise ValueError("PCAP import budget: 20 MiB / 5000 packets")
        if not self.lock.acquire(blocking=False):
            raise ValueError("Replay is busy")
        self.cancel.clear()
        record = {
            "id": uid(),
            "origin": "replay",
            "scenario": "local-pcap",
            "actor": actor,
            "status": "RUNNING",
            "processed": 0,
            "started_at": time.time(),
            "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "response": "No live authority",
            "network_access": False,
        }
        record["run_id"] = record["id"]
        self.store.put("lab_runs", record)
        start = time.perf_counter()
        try:
            pipeline = Pipeline(self.store, self.settings)
            with PcapReader(str(path)) as packets:
                for packet in packets:
                    if (
                        record["processed"] >= max_packets
                        or self.cancel.is_set()
                        or time.perf_counter() - start > 120
                    ):
                        raise ValueError("Import budget reached or cancelled")
                    pipeline.packet(packet, Origin.REPLAY, record["id"], "pcap")
                    record["processed"] += 1
            record["status"] = "COMPLETE"
            record["assessment"] = "Imported observations; no external expected-detection assertion supplied"
        except Exception as error:
            record.update(status="INCOMPLETE", error=type(error).__name__)
        finally:
            record.update(finished_at=time.time(), elapsed_seconds=time.perf_counter() - start)
            self.store.put("lab_runs", record)
            self.store.audit(
                actor,
                "pcap.imported",
                record["id"],
                record["status"],
                artifact_sha256=record["artifact_sha256"],
            )
            self.lock.release()
        return record


def write_fixture(identity, path):
    if identity not in SCENARIOS or SCENARIOS[identity]["service_events"]:
        raise ValueError("Select a packet scenario for PCAP export")
    path = Path(path)
    if path.exists():
        raise ValueError("Fixture output must be a new file")
    wrpcap(str(path), list(fixtures(identity)))
