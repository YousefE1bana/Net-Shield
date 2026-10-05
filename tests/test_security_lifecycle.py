import time
import pytest
from netshield.store import Store
from netshield.settings import Settings
from netshield.replay import Replay
from netshield.investigations import Investigations
from netshield.reports import Reports
from netshield.maintenance import maintain


def test_retention_uses_ingestion_not_recorded_time_and_keeps_active_actions(tmp_path):
    store = Store(tmp_path / "db")
    old = time.time() - 100 * 86400
    stale = store.put("events", {"origin": "replay", "event_time": 1, "ingest_time": old})
    recent = store.put("events", {"origin": "replay", "event_time": 1})
    action = store.put("actions", {"status": "UNKNOWN", "ingest_time": old})
    counts = store.prune()
    assert counts["events"] == 1 and store.get("events", stale["id"]) is None
    assert store.get("events", recent["id"]) and store.get("actions", action["id"])


def test_backup_recovers_investigation_and_bounded_report(tmp_path):
    settings = Settings(data_dir=tmp_path)
    store = Store(settings.database)
    run = Replay(store, settings).run("port-scan", "test")
    incident = store.list("incidents", {"run": run["id"]})["items"][0]
    Investigations(store, settings).change(
        "incidents",
        incident["id"],
        {"status": "RESOLVED", "note": "Authorized local fixture reviewed"},
        "analyst",
    )
    dest = store.backup(tmp_path / "backup.db")
    restored = Store(dest)
    snapshot = Reports(restored).snapshot(incident["id"], generated_at=42)
    assert (
        snapshot["incident"]["status"] == "RESOLVED"
        and snapshot["incident"]["notes"][0]["actor"] == "analyst"
    )
    assert Reports.json(snapshot) == Reports.json(Reports(restored).snapshot(incident["id"], generated_at=42))
    with pytest.raises(ValueError):
        store.backup(dest)


def test_exception_revoke_preserves_evidence_and_restores_detection(tmp_path):
    settings = Settings(data_dir=tmp_path)
    store = Store(settings.database)
    investigate = Investigations(store, settings)
    exception = investigate.exception(
        {
            "origin": "replay",
            "source_ip": "10.77.0.2",
            "rule_id": "NS-RECON-VERTICAL",
            "duration": 600,
            "reason": "Authorized scanner",
        },
        "analyst",
    )
    first = Replay(store, settings).run("port-scan", "test")
    assert "NS-RECON-VERTICAL" not in first["observed_rules"]
    assert store.list("events", {"run": first["id"]})["total"] == 18
    investigate.revoke(exception["id"], "analyst")
    second = Replay(store, settings).run("port-scan", "test")
    assert "NS-RECON-VERTICAL" in second["observed_rules"]
    assert store.get("exceptions", exception["id"])["status"] == "REVOKED"


def test_stale_sensor_maintenance_creates_truthful_operational_alert(tmp_path):
    settings = Settings(data_dir=tmp_path)
    store = Store(settings.database)
    store.put(
        "sensors",
        {
            "id": "local",
            "origin": "capture",
            "capture_state": "running",
            "capture_heartbeat": time.time() - 20,
        },
    )
    maintain(store, settings)
    assert store.get("sensors", "local")["capture_state"] == "stale"
    alerts = store.list("alerts", {"rule": "NS-OPS-FAILURE"})["items"]
    assert len(alerts) == 1 and alerts[0]["origin"] == "service_event" and not alerts[0]["response_eligible"]


def test_cancelled_replay_is_incomplete_and_unlocks(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path)
    store = Store(settings.database)
    runner = Replay(store, settings)
    import netshield.replay as replay

    actual = replay.fixtures

    def cancelling(name):
        for index, packet in enumerate(actual(name)):
            if index == 1:
                runner.cancel.set()
            yield packet

    monkeypatch.setattr(replay, "fixtures", cancelling)
    result = runner.run("port-scan", "test")
    assert result["status"] == "INCOMPLETE" and result["processed"] == 1
    assert runner.current is None and not runner.lock.locked()
