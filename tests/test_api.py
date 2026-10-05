import pytest
from netshield.settings import Settings
from netshield.web import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(data_dir=tmp_path))
    app.extensions["store"].create_operator("analyst", "long-test-password")
    client = app.test_client()
    nonce = client.get("/auth/session").json["csrf"]
    result = client.post(
        "/auth/login", json={"username": "analyst", "password": "long-test-password", "csrf": nonce}
    )
    client.csrf = result.json["csrf"]
    return client


def test_resource_schema_filters_and_limit(client):
    assert client.get("/api/v2/flows?limit=2&origin=replay").json["items"] == []
    assert client.get("/api/v2/flows?limit=999").status_code == 400
    assert client.get("/api/v2/flows?unknown=x").status_code == 400
    assert client.get("/api/v2/metrics").json["schema_version"] == 2
    assert len(client.get("/api/v2/rules").json["items"]) >= 20
    assert client.get("/api/v2/sessions").status_code == 404


def test_lab_accepts_only_named_offline_scenario(client):
    value = client.post(
        "/api/v2/lab-runs",
        json={"scenario": "port-scan", "origin": "capture"},
        headers={"X-CSRF-Token": client.csrf},
    )
    assert value.status_code == 400
    value = client.post(
        "/api/v2/lab-runs", json={"scenario": "internet-launcher"}, headers={"X-CSRF-Token": client.csrf}
    )
    assert value.status_code == 400


def test_status_does_not_invent_capture_health(client):
    result = client.get("/api/v2/status").json
    assert result["live_capture"] == "stopped"
    assert result["kernel_drop_count"] is None
    assert result["automatic_response"] is False


def test_incident_export_is_authenticated_download(client):
    app = client.application
    incident = app.extensions["store"].put(
        "incidents", {"origin": "replay", "status": "OPEN", "alert_ids": []}
    )
    result = client.get("/api/v2/incidents/" + incident["id"] + "/report.pdf")
    assert result.status_code == 200
    assert result.headers["Content-Type"] == "application/pdf"
    assert result.headers["Content-Disposition"].startswith("attachment;")
    assert result.data.startswith(b"%PDF")
