import time

import pytest

from netshield.investigations import Investigations
from netshield.settings import Settings
from netshield.store import Store


@pytest.fixture
def investigation(tmp_path):
    store = Store(tmp_path / "test.db")
    return Investigations(store, Settings(data_dir=tmp_path))


def test_lifecycle_and_notes_survive_restart(investigation):
    store = investigation.store
    alert = store.put("alerts", {"status": "OPEN", "origin": "replay", "occurrences": 4})
    investigation.change(
        "alerts", alert["id"], {"status": "ACKNOWLEDGED", "note": "Reviewed evidence"}, "analyst"
    )
    investigation.change("alerts", alert["id"], {"status": "RESOLVED"}, "analyst")
    result = Store(store.path).get("alerts", alert["id"])
    assert result["status"] == "RESOLVED" and result["occurrences"] == 4
    assert result["notes"][0]["text"] == "Reviewed evidence"
    assert store.list("audit")["total"] == 2


def test_exceptions_are_scoped_expiring_and_distinct_from_protection(investigation):
    item = investigation.exception(
        {
            "rule_id": "NS-RECON-VERTICAL",
            "source_ip": "10.77.0.2",
            "origin": "replay",
            "duration": 600,
            "reason": "Approved scanner",
        },
        "analyst",
    )
    assert time.time() < item["expires_at"] < time.time() + 601
    assert investigation.store.list("protections")["total"] == 0
    with pytest.raises(ValueError):
        investigation.exception(
            {"rule_id": "NS-RECON-VERTICAL", "origin": "capture", "duration": 600, "reason": "Broad"},
            "analyst",
        )


def test_detach_keeps_alert_evidence(investigation):
    store = investigation.store
    alert = store.put("alerts", {"status": "OPEN"})
    incident = store.put("incidents", {"status": "OPEN", "alert_ids": [alert["id"]]})
    store.put(
        "incident_links",
        {
            "id": incident["id"] + ":" + alert["id"],
            "incident_id": incident["id"],
            "alert_id": alert["id"],
            "status": "LINKED",
        },
    )
    investigation.detach(incident["id"], alert["id"], "Unrelated activity", "analyst")
    assert store.get("incidents", incident["id"])["alert_ids"] == []
    assert store.get("alerts", alert["id"]) is not None
    assert store.list("incident_links")["items"][0]["status"] == "DETACHED"
