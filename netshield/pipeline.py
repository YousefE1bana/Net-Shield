"""One analysis owner, transactional metadata/flow/metric/finding writes."""

from collections import OrderedDict
import hashlib
import json
import threading
import time
from .events import Origin, normalize_packet, normalize_service
from .rules import RuleEngine
from .store import uid

SEVERITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def key(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


class Pipeline:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        overrides = self.store.get("settings", "rule-overrides") or {}
        self.rules = RuleEngine(settings, overrides.get("overrides", {}))
        self.lock = threading.RLock()
        self.clock = OrderedDict()
        self.late_events = self.writer_failures = self.parser_failures = 0
        self.last_error = ""
        with self.store.transaction() as conn:
            conn.execute("UPDATE v2_rules SET status='ARCHIVED',body=json_set(body,'$.status','ARCHIVED')")
        for rule in self.rules.catalogue.values():
            self.store.put(
                "rules",
                {
                    **rule.record(),
                    "id": rule.id + ":" + rule.version,
                    "key": rule.id + ":" + rule.version,
                    "status": "CURRENT",
                },
            )

    def packet(self, packet, origin=Origin.CAPTURE, run_id="", interface=None):
        try:
            event = normalize_packet(
                packet,
                origin,
                self.settings.sensor_id,
                interface or self.settings.interface or "fixture",
                run_id,
            )
        except (ValueError, TypeError, AttributeError, IndexError):
            self.parser_failures += 1
            raise
        return self.ingest(event)

    def service(self, value, origin=Origin.SERVICE_EVENT, run_id=""):
        return self.ingest(normalize_service(value, origin, self.settings.sensor_id, run_id))

    def partition(self, event):
        return (event.origin, event.run_id, event.sensor_id, event.interface, event.metadata.get("vlan"))

    def ingest(self, event):
        with self.lock:
            partition = self.partition(event)
            last = self.clock.pop(partition, 0)
            late = event.event_time < last
            self.clock[partition] = max(last, event.event_time)
            while len(self.clock) > 128:
                self.clock.popitem(last=False)
            self.late_events += int(late)
            try:
                with self.store.transaction():
                    flow = (
                        self.flow(event)
                        if event.kind == "packet"
                        and event.source_ip
                        and event.target_ip
                        and event.protocol != "ARP"
                        else None
                    )
                    record = {
                        **event.record(),
                        "flow_id": flow["id"] if flow else None,
                        "coverage": {"late_excluded_from_rules": late, "payload_retained": False},
                    }
                    self.store.put("events", record)
                    self.assets(event)
                    findings = [] if late else self.rules.evaluate(event)
                    accepted = []
                    for finding in findings:
                        exception = self.exception(event, finding["rule"].id)
                        if exception:
                            self.store.audit(
                                "rule-engine",
                                "detection.suppressed",
                                event.id,
                                "scoped_exception",
                                exception_id=exception["id"],
                                rule_id=finding["rule"].id,
                                origin=event.origin,
                                run_id=event.run_id,
                            )
                            continue
                        alert = self.finding(event, finding, flow)
                        accepted.append(alert)
                        if flow and alert["id"] not in flow["alert_ids"]:
                            flow["alert_ids"] = (flow["alert_ids"] + [alert["id"]])[-128:]
                            self.store.put("flows", flow)
                    if event.kind == "packet":
                        self.bucket(event, len(accepted))
                    return {"event": record, "alerts": accepted, "flow": flow}
            except Exception as error:
                self.writer_failures += 1
                self.last_error = type(error).__name__
                raise

    def flow(self, event):
        endpoints = sorted(((event.source_ip, event.source_port), (event.target_ip, event.target_port)))
        identity = key(*self.partition(event), event.protocol, endpoints)
        flow = self.store.keyed("flows", identity)
        if flow and event.event_time - flow["last_seen"] > self.settings.flow_idle_seconds:
            flow["key"] = None
            self.store.put("flows", flow)
            flow = None
        if not flow:
            flow = {
                "id": uid(),
                "key": identity,
                "origin": event.origin,
                "run_id": event.run_id,
                "sensor_id": event.sensor_id,
                "interface": event.interface,
                "vlan": event.metadata.get("vlan"),
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "source_port": event.source_port,
                "target_port": event.target_port,
                "protocol": event.protocol,
                "first_seen": event.event_time,
                "last_seen": event.event_time,
                "packets": 0,
                "bytes": 0,
                "forward_packets": 0,
                "reverse_packets": 0,
                "forward_bytes": 0,
                "reverse_bytes": 0,
                "alert_ids": [],
                "direction_basis": "First observed packet; conversation is not an authenticated session",
            }
        forward = (flow["source_ip"], flow["source_port"]) == (event.source_ip, event.source_port)
        direction = "forward" if forward else "reverse"
        flow[direction + "_packets"] += 1
        flow[direction + "_bytes"] += event.length
        flow["packets"] += 1
        flow["bytes"] += event.length
        flow["first_seen"] = min(flow["first_seen"], event.event_time)
        flow["last_seen"] = max(flow["last_seen"], event.event_time)
        flow["duration"] = flow["last_seen"] - flow["first_seen"]
        flow["event_time"] = flow["last_seen"]
        return self.store.put("flows", flow)

    def bucket(self, event, alerts):
        start = int(event.event_time)
        identity = key(*self.partition(event), start, event.protocol)
        bucket = self.store.keyed("metrics", identity) or {
            "id": uid(),
            "key": identity,
            "origin": event.origin,
            "run_id": event.run_id,
            "sensor_id": event.sensor_id,
            "interface": event.interface,
            "protocol": event.protocol,
            "event_time": start,
            "duration": 1,
            "packets": 0,
            "bytes": 0,
            "alert_occurrences": 0,
        }
        bucket["packets"] += 1
        bucket["bytes"] += event.length
        bucket["alert_occurrences"] += alerts
        self.store.put("metrics", bucket)

    def assets(self, event):
        for address, mac in (
            (event.source_ip, event.metadata.get("claimed_mac") or event.metadata.get("source_mac")),
            (event.target_ip, event.metadata.get("target_mac")),
        ):
            if not address or address in ("0.0.0.0", "::"):
                continue
            identity = key(*self.partition(event), address)
            asset = self.store.keyed("assets", identity) or {
                "id": uid(),
                "key": identity,
                "origin": event.origin,
                "run_id": event.run_id,
                "sensor_id": event.sensor_id,
                "interface": event.interface,
                "source_ip": address,
                "addresses": [address],
                "first_seen": event.event_time,
                "last_seen": event.event_time,
                "observed_target_ports": [],
                "mac_observations": [],
                "label": "",
                "identity_limit": "Observed address, not verified device/person identity",
            }
            asset["last_seen"] = max(event.event_time, asset["last_seen"])
            asset["event_time"] = asset["last_seen"]
            if address == event.target_ip and event.target_port:
                asset["observed_target_ports"] = sorted(
                    set(asset["observed_target_ports"] + [event.target_port])
                )[:128]
            # Ethernet addresses on routed IP packets belong to the next hop,
            # not necessarily the observed remote asset. Bind only ARP claims.
            if (
                event.protocol == "ARP"
                and address == event.source_ip
                and mac
                and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
            ):
                asset["mac_observations"] = sorted(set(asset["mac_observations"] + [mac]))[:16]
                asset["binding_conflict"] = len(asset["mac_observations"]) > 1
                if event.protocol == "ARP" and address == event.source_ip:
                    binding_key = key(*self.partition(event), address, mac)
                    binding = self.store.keyed("bindings", binding_key) or {
                        "id": uid(),
                        "key": binding_key,
                        "origin": event.origin,
                        "run_id": event.run_id,
                        "sensor_id": event.sensor_id,
                        "interface": event.interface,
                        "source_ip": address,
                        "mac": mac,
                        "first_seen": event.event_time,
                        "asset_id": asset["id"],
                        "vlan": event.metadata.get("vlan"),
                    }
                    binding.update(last_seen=event.event_time, event_time=event.event_time)
                    self.store.put("bindings", binding)
            self.store.put("assets", asset)

    def exception(self, event, rule_id):
        now = time.time()
        with self.store.connection() as conn:
            rows = conn.execute(
                "SELECT body FROM v2_exceptions WHERE rule_id=? AND (status IS NULL OR status!='REVOKED') AND json_extract(body,'$.expires_at')>? LIMIT 250",
                (rule_id, now),
            ).fetchall()
        exceptions = [json.loads(r[0]) for r in rows]
        return next(
            (
                x
                for x in exceptions
                if x["expires_at"] > now
                and x.get("status") != "REVOKED"
                and x.get("origin") == event.origin
                and (not x.get("source_ip") or x["source_ip"] == event.source_ip)
                and (not x.get("target_ip") or x["target_ip"] == event.target_ip)
                and (not x.get("sensor_id") or x["sensor_id"] == event.sensor_id)
            ),
            None,
        )

    def finding(self, event, finding, flow):
        rule = finding["rule"]
        service_scope = (
            event.target_port
            if rule.category
            in ("Availability", "Authentication", "Connections", "Behavior", "Lateral indicators")
            else None
        )
        identity = key(
            *self.partition(event), rule.id, rule.version, event.source_ip, event.target_ip, service_scope
        )
        alert = self.store.keyed("alerts", identity)
        if alert and (alert["status"] == "RESOLVED" or event.event_time - alert["last_seen"] > 300):
            alert["key"] = None
            self.store.put("alerts", alert)
            alert = None
        if not alert:
            alert = {
                "id": uid(),
                "key": identity,
                "origin": event.origin,
                "run_id": event.run_id,
                "sensor_id": event.sensor_id,
                "interface": event.interface,
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "target_port": event.target_port,
                "rule_id": rule.id,
                "rule_version": rule.version,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "confidence": rule.confidence,
                "status": "OPEN",
                "first_seen": event.event_time,
                "last_seen": event.event_time,
                "occurrences": 0,
                "flow_ids": [],
                "notes": [],
                "response_eligible": rule.response_eligible,
                "attack": rule.attack or None,
                "mapping_rationale": rule.mapping_rationale or None,
            }
        alert.update(event_time=event.event_time, last_seen=event.event_time, evidence=finding["evidence"])
        alert["occurrences"] += 1
        if flow and flow["id"] not in alert["flow_ids"]:
            alert["flow_ids"] = (alert["flow_ids"] + [flow["id"]])[-128:]
        occurrence = self.store.put(
            "occurrences",
            {
                "alert_id": alert["id"],
                "event_id": event.id,
                "flow_id": flow["id"] if flow else None,
                "origin": event.origin,
                "run_id": event.run_id,
                "sensor_id": event.sensor_id,
                "rule_id": rule.id,
                "event_time": event.event_time,
                "evidence": finding["evidence"],
            },
        )
        alert["latest_occurrence_id"] = occurrence["id"]
        incident = self.correlate(event, alert) if not alert.get("analyst_detached") else None
        alert["incident_id"] = incident["id"] if incident else None
        self.store.put("alerts", alert)
        if incident:
            self.store.put(
                "incident_links",
                {
                    "id": key(incident["id"], alert["id"]),
                    "key": key(incident["id"], alert["id"]),
                    "incident_id": incident["id"],
                    "alert_id": alert["id"],
                    "origin": event.origin,
                    "run_id": event.run_id,
                    "event_time": event.event_time,
                    "status": "LINKED",
                },
            )
        return alert

    def correlate(self, event, alert):
        identity = key(*self.partition(event), event.source_ip, event.target_ip)
        incident = self.store.keyed("incidents", identity)
        if incident and (incident["status"] == "RESOLVED" or event.event_time - incident["last_seen"] > 300):
            incident["key"] = None
            self.store.put("incidents", incident)
            incident = None
        if not incident:
            incident = {
                "id": uid(),
                "key": identity,
                "origin": event.origin,
                "run_id": event.run_id,
                "sensor_id": event.sensor_id,
                "interface": event.interface,
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "first_seen": event.event_time,
                "last_seen": event.event_time,
                "status": "OPEN",
                "severity": alert["severity"],
                "alert_ids": [],
                "notes": [],
                "grouping_reason": "Same observed source/target, sensor/interface/VLAN and origin/run; activity gap <=300s. No device/person identity or causality asserted.",
            }
        incident["last_seen"] = event.event_time
        incident["event_time"] = event.event_time
        if alert["id"] not in incident["alert_ids"]:
            incident["alert_ids"] = (incident["alert_ids"] + [alert["id"]])[-128:]
        incident["severity"] = max((incident["severity"], alert["severity"]), key=SEVERITY.get)
        return self.store.put("incidents", incident)
