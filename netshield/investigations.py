"""Analyst mutations preserve evidence and record an attributable audit entry."""

import time
import ipaddress
from .events import Origin, host
from .rules import RULES


def text(value, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Text must contain 1–{maximum} characters")
    return value.strip()


class Investigations:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings

    def change(self, resource, identity, changes, actor):
        if resource not in ("alerts", "incidents", "assets"):
            raise ValueError("Resource is not editable")
        allowed = {"label"} if resource == "assets" else {"status", "note"}
        if not changes or set(changes) - allowed:
            raise ValueError("Unsupported analyst fields")
        with self.store.transaction():
            item = self.store.get(resource, identity)
            if not item:
                raise ValueError("Resource not found")
            if "status" in changes:
                if changes["status"] not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
                    raise ValueError("Invalid investigation status")
                item["status"] = changes["status"]
            if "note" in changes:
                notes = item.setdefault("notes", [])
                if len(notes) >= 100:
                    raise ValueError("Note budget reached; export before adding more")
                notes.append({"text": text(changes["note"]), "actor": actor, "time": time.time()})
            if "label" in changes:
                item["label"] = text(changes["label"], 80)
            item["analyst_updated_at"] = time.time()
            self.store.put(resource, item)
            self.store.audit(actor, resource + ".updated", identity, "success", changes=changes)
            return item

    def exception(self, value, actor):
        allowed = {"rule_id", "source_ip", "target_ip", "sensor_id", "origin", "duration", "reason"}
        if (
            set(value) - allowed
            or not isinstance(value.get("rule_id"), str)
            or value.get("rule_id") not in {r.id for r in RULES}
        ):
            raise ValueError("A known rule and explicit scope are required")
        origin = Origin(value.get("origin"))
        source = host(value["source_ip"]) if value.get("source_ip") else ""
        target = host(value["target_ip"]) if value.get("target_ip") else ""
        if not (source or target):
            raise ValueError("Exception requires a source or target; blanket suppression is refused")
        duration = value.get("duration")
        if type(duration) is not int or not 60 <= duration <= 86400:
            raise ValueError("Exception duration must be 60–86400 seconds")
        with self.store.connection() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM v2_exceptions WHERE status!='REVOKED' AND json_extract(body,'$.expires_at')>?",
                (time.time(),),
            ).fetchone()[0]
        if active >= 200:
            raise ValueError("Active exception budget reached; revoke an entry")
        if value.get("sensor_id"):
            text(value["sensor_id"], 64)
        item = self.store.put(
            "exceptions",
            {
                **value,
                "source_ip": source,
                "target_ip": target,
                "origin": origin,
                "reason": text(value.get("reason"), 500),
                "actor": actor,
                "expires_at": time.time() + duration,
                "status": "ACTIVE",
            },
        )
        self.store.audit(actor, "exception.created", item["id"], "success", scope=value)
        return item

    def revoke(self, identity, actor):
        item = self.store.get("exceptions", identity)
        if not item:
            raise ValueError("Exception not found")
        item.update(status="REVOKED", expires_at=time.time(), revoked_by=actor)
        self.store.put("exceptions", item)
        self.store.audit(actor, "exception.revoked", identity, "success")
        return item

    def protect(self, network, reason, actor):
        network = str(ipaddress.ip_network(network, strict=True))
        if self.store.list("protections", limit=1)["total"] >= 200:
            raise ValueError("Protection budget reached")
        item = self.store.put(
            "protections", {"network": network, "reason": text(reason, 500), "actor": actor}
        )
        self.store.audit(actor, "response.protected", item["id"], "success", network=network)
        return item

    def unprotect(self, identity, reason, actor):
        reason = text(reason, 500)
        with self.store.transaction() as conn:
            item = self.store.get("protections", identity)
            if not item:
                raise ValueError("Protection not found")
            conn.execute("DELETE FROM v2_protections WHERE id=?", (identity,))
            self.store.audit(
                actor,
                "response.protection_removed",
                identity,
                "success",
                network=item["network"],
                reason=reason,
            )
        return {"status": "Removed app-level protection; independent helper policy still applies"}

    def detach(self, incident_id, alert_id, reason, actor):
        reason = text(reason, 500)
        with self.store.transaction():
            incident = self.store.get("incidents", incident_id)
            if not incident or alert_id not in incident.get("alert_ids", []):
                raise ValueError("Alert is not linked to this incident")
            incident["alert_ids"].remove(alert_id)
            self.store.put("incidents", incident)
            for link in self.store.list("incident_links", {"incident_id": incident_id}, limit=250)["items"]:
                if link["alert_id"] == alert_id:
                    link.update(status="DETACHED", reason=reason, actor=actor, detached_at=time.time())
                    self.store.put("incident_links", link)
            alert = self.store.get("alerts", alert_id)
            if alert and alert.get("incident_id") == incident_id:
                alert.update(incident_id=None, analyst_detached=True)
                self.store.put("alerts", alert)
            self.store.audit(
                actor, "incident.detached", incident_id, "success", alert_id=alert_id, reason=reason
            )
            return incident
