import pytest
from scapy.all import Ether, IP, IPv6, TCP, ARP, Dot1Q


def pipeline(tmp_path):
    from netshield.settings import Settings
    from netshield.pipeline import Pipeline
    from netshield.store import Store

    settings = Settings(data_dir=tmp_path)
    return Pipeline(Store(settings.database), settings)


def test_packet_time_ipv6_vlan_and_transport_are_preserved(tmp_path):
    from netshield.events import normalize_packet, Origin

    packet = (
        Ether()
        / Dot1Q(vlan=7)
        / IPv6(src="fd00::1", dst="fd00::2")
        / TCP(sport=1234, dport=443, flags="S", seq=1)
    )
    packet.time = 123.25
    event = normalize_packet(packet, Origin.REPLAY, "test", "fixture", "run")
    assert event.event_time == 123.25
    assert event.source_ip == "fd00::1"
    assert event.protocol == "TCP"
    assert event.metadata["vlan"] == 7
    assert "payload" not in event.metadata


def test_bidirectional_flows_and_metric_buckets_are_durable(tmp_path):
    from netshield.events import Origin

    engine = pipeline(tmp_path)
    first = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=44000, dport=80, flags="S", seq=1)
    second = IP(src="192.0.2.20", dst="192.0.2.10") / TCP(sport=80, dport=44000, flags="SA", seq=2)
    first.time = 100
    second.time = 102
    engine.packet(first, Origin.REPLAY, "flow-run")
    engine.packet(second, Origin.REPLAY, "flow-run")
    flows = engine.store.list("flows")["items"]
    assert len(flows) == 1
    assert flows[0]["packets"] == 2
    assert flows[0]["forward_packets"] == 1 and flows[0]["reverse_packets"] == 1
    assert flows[0]["bytes"] == len(first) + len(second)
    assert flows[0]["duration"] == 2
    assert sum(x["packets"] for x in engine.store.list("metrics")["items"]) == 2
    assert len(engine.store.list("assets")["items"]) == 2


def test_vertical_scan_scopes_target_and_retransmission(tmp_path):
    from netshield.events import Origin

    engine = pipeline(tmp_path)
    for i in range(15):
        packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=41000, dport=1000 + i, seq=i, flags="S")
        packet.time = 100 + i / 10
        engine.packet(packet, Origin.REPLAY, "scan")
    alerts = engine.store.list("alerts")["items"]
    vertical = [a for a in alerts if a["rule_id"] == "NS-RECON-VERTICAL"]
    assert len(vertical) == 1 and vertical[0]["evidence"]["observed"] == 15
    engine.packet(packet, Origin.REPLAY, "scan")
    assert engine.store.get("alerts", vertical[0]["id"])["occurrences"] == 1
    assert engine.store.list("incidents")["total"] >= 1
    other = pipeline(tmp_path / "other")
    for i in range(14):
        packet = IP(src="192.0.2.10", dst=f"192.0.2.{20 + i % 2}") / TCP(
            sport=42000, dport=2000 + i, seq=i, flags="S"
        )
        packet.time = 100 + i / 10
        other.packet(packet, Origin.REPLAY, "mixed")
    assert not any(a["rule_id"] == "NS-RECON-VERTICAL" for a in other.store.list("alerts")["items"])


def test_ssh_syn_is_not_failed_authentication_and_service_contract_rejects_origin(tmp_path):
    from netshield.events import Origin, normalize_service

    engine = pipeline(tmp_path)
    for i in range(8):
        packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=44000 + i, dport=22, flags="S", seq=i)
        packet.time = 100 + i
        engine.packet(packet, Origin.REPLAY, "network")
    assert not any(a["rule_id"] == "NS-AUTH-SSH" for a in engine.store.list("alerts")["items"])
    with pytest.raises(ValueError, match="provenance"):
        normalize_service(
            {"kind": "ssh_auth", "origin": "capture", "source_ip": "192.0.2.10"},
            Origin.SERVICE_EVENT,
            "local",
            "",
        )
    for i in range(5):
        engine.service(
            {
                "kind": "ssh_auth",
                "event_time": 100 + i,
                "source_ip": "192.0.2.10",
                "target_ip": "192.0.2.20",
                "outcome": "failure",
            },
            Origin.REPLAY,
            "auth",
        )
    assert any(a["rule_id"] == "NS-AUTH-SSH" for a in engine.store.list("alerts")["items"])


def test_arp_is_segment_scoped_and_not_mitm_proof(tmp_path):
    from netshield.events import Origin

    engine = pipeline(tmp_path)
    for i, mac in enumerate(["02:00:00:00:00:01", "02:00:00:00:00:02"]):
        packet = Ether(src=mac) / ARP(op=2, psrc="192.0.2.20", hwsrc=mac, pdst="192.0.2.10")
        packet.time = 100 + i
        engine.packet(packet, Origin.REPLAY, "arp")
    alert = engine.store.list("alerts")["items"][0]
    assert alert["rule_id"] == "NS-L2-ARP-CONFLICT"
    assert alert["response_eligible"] is False
    assert "MITM confirmed" not in alert["description"]
    assert engine.store.list("bindings")["total"] == 2


def test_queue_overload_and_writer_failure_are_visible(tmp_path):
    engine = pipeline(tmp_path)
    from netshield.capture import Intake

    intake = Intake(engine, capacity=1)
    intake.offer(b"x")
    intake.offer(b"y")
    assert intake.health()["queue_overflow"] == 1
    assert intake.health()["kernel_packet_loss"] == "Unknown"


def test_replay_state_is_partitioned_and_occurrences_are_retained(tmp_path):
    from netshield.events import Origin

    engine = pipeline(tmp_path)
    for run in ["first", "second"]:
        for i in range(17):
            packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
                sport=44000, dport=1000 + i, seq=i, flags="S"
            )
            packet.time = 100 + i / 10
            engine.packet(packet, Origin.REPLAY, run)
    alerts = [a for a in engine.store.list("alerts")["items"] if a["rule_id"] == "NS-RECON-VERTICAL"]
    assert len(alerts) == 2
    assert all(a["occurrences"] == 3 for a in alerts)
    assert engine.store.list("occurrences")["total"] >= 6
    assert len({a["run_id"] for a in alerts}) == 2
