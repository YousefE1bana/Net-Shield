import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from scapy.all import ARP, IP, TCP
from netshield.events import Origin, normalize_packet
from netshield.rules import RuleEngine
from netshield.settings import Settings
from netshield.store import Store
from netshield.web import create_app
from test_response import setup


def test_malformed_helper_reply_cannot_claim_enforcement(tmp_path):
    response, alert, backend = setup(tmp_path)
    backend.request = lambda *_: {"targets": "10.77.0.2", "scope": "invalid-shape"}
    item = response.request(alert["id"], 60, "Reviewed", "analyst")
    assert item["status"] == "UNKNOWN"
    assert item["verification"] == "unavailable"


def test_current_schema_missing_columns_is_rejected_without_changes(tmp_path):
    path = tmp_path / "state.db"
    Store(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE v2_events")
        db.execute("CREATE TABLE v2_events(id TEXT)")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="schema"):
        Store(path)
    assert path.read_bytes() == before


def test_unknown_version_one_is_rejected_without_migration(tmp_path):
    path = tmp_path / "other.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE precious(value TEXT)")
        db.execute("PRAGMA user_version=1")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="schema"):
        Store(path)
    assert path.read_bytes() == before


def test_independent_response_brokers_serialize_same_target(tmp_path):
    from netshield.response import Response

    response, alert, backend = setup(tmp_path)
    second = Response(Store(response.store.path), response.settings, backend)

    def request(broker):
        try:
            return broker.request(alert["id"], 60, "Concurrent reviewed request", "analyst")["id"]
        except ValueError as error:
            assert "active" in str(error)
            return None

    with ThreadPoolExecutor(2) as pool:
        ids = list(pool.map(request, [response, second]))
    assert backend.calls.count("add") == 1
    assert len({x for x in ids if x}) == 1
    assert second.request(alert["id"], 60, "Retry after verification", "analyst")["id"] in ids


@pytest.mark.parametrize("cancel", [False, True])
def test_owned_lab_failure_or_cancellation_cleans_only_created_names(tmp_path, monkeypatch, cancel):
    import netshield.lab as lab

    monkeypatch.setattr(lab, "authorized", lambda _: None)
    calls = []

    def command(arguments, input=None, timeout=5):
        calls.append(arguments)
        if arguments[1:3] == ["link", "add"]:
            if cancel:
                raise KeyboardInterrupt()
            raise OSError("failure before any traffic")
        return ""

    monkeypatch.setattr(lab, "command", command)
    result = lab.run_lab(Store(tmp_path / "lab.db"), Settings(data_dir=tmp_path), True)
    created = [x[-1] for x in calls if x[1:3] == ["netns", "add"]]
    removed = [x[-1] for x in calls if x[1:3] == ["netns", "delete"]]
    assert result["status"] == "INCOMPLETE"
    assert len(created) == 2 and removed == list(reversed(created))
    assert result["cleanup_remaining"] == []
    assert all(x.startswith(("ns-a-", "ns-v-")) for x in removed)


def test_arp_change_outside_window_and_jitter_are_benign():
    engine = RuleEngine(Settings())

    def observe(packet, when):
        packet.time = when
        return {
            x["rule"].id
            for x in engine.evaluate(normalize_packet(packet, Origin.REPLAY, "fixture", "test", "r"))
        }

    first = ARP(op=2, psrc="10.77.0.10", pdst="10.77.0.2", hwsrc="02:00:00:00:00:01")
    second = first.copy()
    second.hwsrc = "02:00:00:00:00:02"
    assert "NS-L2-ARP-CONFLICT" not in observe(first, 100)
    assert "NS-L2-ARP-CONFLICT" not in observe(second, 500)
    assert "NS-L2-ARP-CONFLICT" in observe(first, 501)
    for index, when in enumerate([600, 610, 640, 645, 700, 703, 770, 800]):
        packet = IP(src="10.77.0.2", dst="198.51.100.2") / TCP(
            sport=40000 + index, dport=443, flags="S", seq=index
        )
        assert "NS-BEHAVIOR-BEACON" not in observe(packet, when)


def test_viewer_mutation_origin_and_secure_cookie_boundaries(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, secure_cookie=True))
    app.extensions["store"].create_operator("viewer", "long-viewer-password", "viewer")
    client = app.test_client()
    csrf = client.get("/auth/session", base_url="https://localhost").json["csrf"]
    result = client.post(
        "/auth/login",
        base_url="https://localhost",
        json={"username": "viewer", "password": "long-viewer-password", "csrf": csrf},
    )
    cookie = result.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    token = result.json["csrf"]
    headers = {"X-CSRF-Token": token}
    for path in ["lab-runs", "actions", "settings", "rule-config", "exceptions"]:
        assert (
            client.post("/api/v2/" + path, base_url="https://localhost", json={}, headers=headers).status_code
            == 403
        )
    assert (
        client.post(
            "/auth/logout",
            base_url="https://localhost",
            headers={**headers, "Origin": "https://foreign.example"},
            json={},
        ).status_code
        == 403
    )
    assert client.get("/api/v2/status", headers={"Host": "foreign.example"}).status_code == 400


def test_rule_statistics_and_incident_timeline_use_retained_evidence(tmp_path):
    app = create_app(Settings(data_dir=tmp_path))
    store = app.extensions["store"]
    store.create_operator("analyst", "long-test-password")
    client = app.test_client()
    csrf = client.get("/auth/session").json["csrf"]
    client.post("/auth/login", json={"username": "analyst", "password": "long-test-password", "csrf": csrf})
    run = app.extensions["replay"].run("port-scan", "test")
    alert = store.list("alerts", {"run": run["id"], "rule": "NS-RECON-VERTICAL"})["items"][0]
    rules = client.get("/api/v2/rules?status=CURRENT").json["items"]
    rule = next(r for r in rules if r["rule_id"] == alert["rule_id"])
    assert rule["alert_count"] == 1 and rule["last_triggered"] == alert["event_time"]
    snapshot = client.get("/api/v2/incidents/" + alert["incident_id"] + "/evidence").json
    assert snapshot["occurrences"] and {a["id"] for a in snapshot["alerts"]} == set(
        snapshot["incident"]["alert_ids"]
    )
    assert len(snapshot["occurrences"]) <= 100


def test_outbound_service_policy_is_explicit_and_typed():
    with pytest.raises(ValueError):
        Settings(approved_outbound_ports=(True,))
    with pytest.raises(ValueError):
        Settings(approved_outbound_ports=())
    engine = RuleEngine(Settings(approved_outbound_ports=(8443,)))
    packet = IP(src="10.77.0.2", dst="198.51.100.2") / TCP(sport=40001, dport=8443, flags="S", seq=1)
    packet.time = 100
    event = normalize_packet(packet, Origin.REPLAY, "one", "fixture", "run")
    assert "NS-EGRESS-SERVICE" not in {x["rule"].id for x in engine.evaluate(event)}
    packet[TCP].dport = 443
    packet.time = 101
    findings = engine.evaluate(normalize_packet(packet, Origin.REPLAY, "one", "fixture", "run"))
    finding = next(x for x in findings if x["rule"].id == "NS-EGRESS-SERVICE")
    assert finding["evidence"]["approved_ports"] == [8443]
