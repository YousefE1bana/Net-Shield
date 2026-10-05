"""Trust/persistence contracts; failures here block response and UI work."""

import sqlite3
import pytest


def test_legacy_schema_is_preserved_and_versioned(tmp_path):
    from netshield.store import Store

    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE alerts(id INTEGER PRIMARY KEY, description TEXT); INSERT INTO alerts VALUES(1,'historical'); CREATE TABLE blocked_ips(id INTEGER); CREATE TABLE traffic_logs(id INTEGER);"
    )
    conn.close()
    store = Store(path)
    with store.connection() as db:
        assert db.execute("SELECT description FROM alerts").fetchone()[0] == "historical"
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert list(tmp_path.glob("legacy.db.before-v2-*.bak"))


def test_unknown_database_is_not_overwritten(tmp_path):
    from netshield.store import Store

    path = tmp_path / "other.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE precious(value TEXT)")
    with pytest.raises(ValueError, match="Unrecognized"):
        Store(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='precious'").fetchone()


def test_evidence_survives_restart_and_transaction_rollback(tmp_path):
    from netshield.store import Store

    path = tmp_path / "evidence.db"
    store = Store(path)
    record = store.put(
        "events", {"origin": "replay", "run_id": "run-a", "event_time": 42, "source_ip": "192.0.2.1"}
    )
    assert Store(path).get("events", record["id"]) == record
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.put("events", {"id": "rollback", "event_time": 43})
            raise RuntimeError("writer error")
    assert store.get("events", "rollback") is None


def test_defaults_have_no_capture_or_response_authority(tmp_path):
    from netshield.settings import Settings

    settings = Settings(data_dir=tmp_path)
    assert settings.auto_response is False
    assert settings.response_enabled is False
    assert settings.host == "127.0.0.1"


def test_no_default_operator_and_legacy_controls_are_not_anonymous(tmp_path):
    from netshield.web import create_app
    from netshield.settings import Settings

    app = create_app(Settings(data_dir=tmp_path))
    client = app.test_client()
    for url in [
        "/api/v2/status",
        "/api/engine/start",
        "/api/mitigation/block",
        "/api/simulate",
        "/socket.io/",
    ]:
        result = client.get(url) if url.endswith("status") else client.post(url, json={})
        assert result.status_code in (401, 404, 410)
    assert client.get("/").status_code == 302
    assert app.extensions["store"].operators() == []


def test_session_csrf_logout_and_authorization(tmp_path):
    from netshield.web import create_app
    from netshield.settings import Settings

    app = create_app(Settings(data_dir=tmp_path))
    app.extensions["store"].create_operator("analyst", "correct horse battery staple", "operator")
    client = app.test_client()
    preflight = client.get("/auth/session").get_json()
    assert (
        client.post(
            "/auth/login", json={"username": "analyst", "password": "correct horse battery staple"}
        ).status_code
        == 403
    )
    result = client.post(
        "/auth/login",
        json={"username": "analyst", "password": "correct horse battery staple", "csrf": preflight["csrf"]},
    )
    assert result.status_code == 200
    token = result.get_json()["csrf"]
    assert client.get("/api/v2/status").status_code == 200
    assert client.post("/api/v2/settings", json={}).status_code == 403
    assert client.post("/api/v2/settings", json={}, headers={"X-CSRF-Token": token}).status_code == 403
    assert client.post("/auth/logout", json={}, headers={"X-CSRF-Token": token}).status_code == 200
    assert client.get("/api/v2/status").status_code == 401


def test_login_rate_limit_and_no_password_leak(tmp_path):
    from netshield.web import create_app
    from netshield.settings import Settings

    app = create_app(Settings(data_dir=tmp_path))
    client = app.test_client()
    csrf = client.get("/auth/session").get_json()["csrf"]
    results = [
        client.post("/auth/login", json={"username": "unknown", "password": "wrong", "csrf": csrf})
        for _ in range(12)
    ]
    assert results[-1].status_code == 429
    assert "wrong" not in str(app.extensions["store"].list("audit")["items"])
