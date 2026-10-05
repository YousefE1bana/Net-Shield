"""Manual response broker. Historical/replay evidence has no live authority."""

import ipaddress
import json
import socket
import threading
import time
from .investigations import text
from .locks import response_lock


def verified_targets(reply):
    if not isinstance(reply, dict) or not isinstance(reply.get("targets"), list):
        raise ValueError("Invalid helper evidence")
    targets = reply["targets"]
    if len(targets) > 250 or any(not isinstance(t, str) for t in targets):
        raise ValueError("Invalid helper target budget")
    if any(str(ipaddress.ip_address(t)) != t for t in targets):
        raise ValueError("Noncanonical helper evidence")
    return targets


class HelperClient:
    def __init__(self, path):
        self.path = path

    def request(self, operation, target="", ttl=0):
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("Unix response helper unavailable")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(self.path)
            client.sendall(
                json.dumps({"operation": operation, "target": target, "ttl": ttl}).encode() + b"\n"
            )
            data = bytearray()
            while b"\n" not in data and len(data) <= 65536:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > 65536 or b"\n" not in data:
                raise OSError("Invalid helper reply")
            reply = json.loads(data)
            verified_targets(reply)
            if reply.get("error"):
                raise OSError("Response helper refused request")
            return reply


class Response:
    def __init__(self, store, settings, backend=None):
        self.store, self.settings = store, settings
        self.backend = backend or HelperClient(settings.helper_socket)
        self.lock = threading.RLock()

    def validate_target(self, value, dry_run=False):
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
            raise ValueError("Infrastructure/special-use addresses cannot be response targets")
        protected = list(self.settings.protected_networks)
        protected.extend(x["network"] for x in self.store.list("protections", limit=250)["items"])
        if any(address in ipaddress.ip_network(n) for n in protected):
            raise ValueError("Target is protected from response")
        if not dry_run and not any(
            address in ipaddress.ip_network(n) for n in self.settings.response_networks
        ):
            raise ValueError("Target is outside the locally configured response scope")
        return str(address)

    def transition(self, item, status, actor="response-engine", **values):
        if item.get("status") == status and all(item.get(k) == v for k, v in values.items()):
            return item
        item.update(status=status, **values)
        item.setdefault("history", []).append(
            {"status": status, "time": time.time(), "actor": actor, **values}
        )
        item["history"] = item["history"][-500:]
        self.store.put("actions", item)
        self.store.audit(
            actor,
            "response." + status.lower(),
            item["id"],
            status,
            target_ip=item["target_ip"],
            origin=item["origin"],
        )
        return item

    def request(self, alert_id, ttl, reason, actor, dry_run=False):
        if type(ttl) is not int or not 60 <= ttl <= 3600 or type(dry_run) is not bool:
            raise ValueError("Response TTL must be 60–3600 seconds")
        reason = text(reason, 500)
        alert = self.store.get("alerts", alert_id)
        if not alert or not alert.get("response_eligible"):
            raise ValueError("Rule evidence is not eligible for manual IP response")
        if not dry_run and (alert.get("origin") not in ("capture", "service_event") or alert.get("run_id")):
            raise ValueError("Replay and isolated-lab evidence cannot authorize a live block")
        if not dry_run and not self.settings.response_enabled:
            raise ValueError("Live response is disabled by local configuration")
        target = self.validate_target(alert["source_ip"], dry_run)
        identity = ("dry:" if dry_run else "live:") + target
        with self.lock, response_lock(str(self.store.path) + ".response-lock"):
            existing = self.store.keyed("actions", identity)
            if existing and existing["status"] not in ("REMOVED", "FAILED"):
                return existing
            if existing:
                existing["key"] = None
                self.store.put("actions", existing)
            if len(self.active()) >= 250:
                raise ValueError("Active response budget reached; reconcile before adding targets")
            item = self.store.put(
                "actions",
                {
                    "key": identity,
                    "target_ip": target,
                    "source_ip": target,
                    "alert_id": alert_id,
                    "incident_id": alert.get("incident_id"),
                    "origin": alert["origin"],
                    "run_id": alert.get("run_id", ""),
                    "status": "REQUESTED",
                    "requested_by": actor,
                    "reason": reason,
                    "created_at": time.time(),
                    "expires_at": time.time() + ttl,
                    "ttl": ttl,
                    "backend": "nftables",
                    "dry_run": dry_run,
                    "verification": "not_enforced",
                    "history": [],
                },
            )
            self.transition(item, "VALIDATED", actor)
            if dry_run:
                return item
            self.transition(item, "APPLYING", actor)
            try:
                reply = self.backend.request("add", target, ttl)
                if target not in verified_targets(reply):
                    return self.transition(item, "FAILED", verification="kernel_absent")
                return self.transition(
                    item,
                    "APPLIED",
                    verification="kernel_present",
                    verified_at=time.time(),
                    helper_scope=reply.get("scope"),
                )
            except (OSError, ValueError, KeyError):
                return self.transition(item, "UNKNOWN", verification="unavailable")

    def remove(self, identity, actor):
        with self.lock, response_lock(str(self.store.path) + ".response-lock"):
            return self._remove(identity, actor)

    def _remove(self, identity, actor):
        item = self.store.get("actions", identity)
        if not item:
            raise ValueError("Response action not found")
        if not item.get("dry_run") and (
            item.get("origin") not in ("capture", "service_event") or item.get("run_id")
        ):
            raise ValueError("Lab/replay actions have no host-helper removal authority")
        if item["status"] == "REMOVED":
            return item
        if item["dry_run"]:
            return self.transition(item, "REMOVED", actor, verification="not_enforced")
        # Removal also requires the independent helper's owned-resource check.
        self.transition(item, "REMOVING", actor)
        try:
            reply = self.backend.request("remove", item["target_ip"])
            if item["target_ip"] in verified_targets(reply):
                return self.transition(item, "UNKNOWN", verification="kernel_still_present")
            return self.transition(item, "REMOVED", verification="kernel_absent", verified_at=time.time())
        except (OSError, ValueError, KeyError):
            return self.transition(item, "UNKNOWN", verification="unavailable")

    def active(self):
        with self.store.connection() as conn:
            rows = conn.execute(
                "SELECT body FROM v2_actions WHERE status NOT IN ('REMOVED','FAILED') ORDER BY event_time LIMIT 251"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def reconcile(self):
        with self.lock, response_lock(str(self.store.path) + ".response-lock"):
            active = []
            for action in self.active():
                if action["dry_run"]:
                    if action["expires_at"] <= time.time():
                        self.transition(
                            action, "REMOVED", verification="not_enforced", removal_reason="Dry-run expiry"
                        )
                elif action.get("origin") in ("capture", "service_event") and not action.get("run_id"):
                    active.append(action)
            if not active:
                return
            try:
                targets = verified_targets(self.backend.request("list"))
            except (OSError, ValueError, KeyError):
                for item in active:
                    self.transition(item, "UNKNOWN", verification="unavailable")
                return
            for item in active:
                if item["target_ip"] not in targets:
                    self.transition(
                        item,
                        "REMOVED",
                        verification="kernel_absent",
                        verified_at=time.time(),
                        removal_reason="Kernel reconciliation",
                    )
                elif item["expires_at"] <= time.time():
                    self.transition(item, "EXPIRING")
                    self._remove(item["id"], "expiry-reconciler")
                elif item["status"] != "APPLIED" or item.get("verification") != "kernel_present":
                    self.transition(item, "APPLIED", verification="kernel_present", verified_at=time.time())
