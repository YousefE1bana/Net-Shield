from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether, IPv6
from scapy.layers.inet6 import IPv6ExtHdrFragment
from netshield.events import Origin, normalize_packet
from netshield.pipeline import Pipeline
from netshield.settings import Settings
from netshield.store import Store


def test_incomplete_http_tls_and_fragments_are_not_requests():
    for packet in [
        IP() / TCP(dport=443) / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        IP() / TCP(dport=80) / Raw(b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\nx"),
        IP(flags="MF") / UDP(dport=53) / DNS(qd=DNSQR(qname="lab.test")),
        IPv6() / IPv6ExtHdrFragment(m=1) / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n"),
    ]:
        event = normalize_packet(packet, Origin.REPLAY, "test", "fixture", "test")
        assert not event.metadata.get("complete_http_requests")
        assert not event.metadata.get("dns_query")
    complete = normalize_packet(
        IP() / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n"), Origin.REPLAY, "test", "fixture"
    )
    assert complete.metadata["complete_http_requests"] == 1


def test_ports_outside_window_do_not_combine_and_late_events_are_evidence_only(tmp_path):
    engine = Pipeline(Store(tmp_path / "test.db"), Settings(data_dir=tmp_path))
    for index in range(14):
        packet = IP(src="10.77.0.2", dst="10.77.0.10") / TCP(
            sport=40000 + index, dport=8000 + index, flags="S", seq=index
        )
        packet.time = 100 + index
        engine.packet(packet, Origin.REPLAY, "run")
    packet = IP(src="10.77.0.2", dst="10.77.0.10") / TCP(sport=40100, dport=8100, flags="S", seq=100)
    packet.time = 200
    engine.packet(packet, Origin.REPLAY, "run")
    packet.time = 102
    result = engine.packet(packet, Origin.REPLAY, "run")
    assert result["event"]["coverage"]["late_excluded_from_rules"] is True
    assert not engine.store.list("alerts", {"rule": "NS-RECON-VERTICAL"})["items"]


def test_gateway_ethernet_mac_is_not_remote_asset_identity(tmp_path):
    engine = Pipeline(Store(tmp_path / "test.db"), Settings(data_dir=tmp_path))
    packet = Ether(src="02:00:00:00:00:01") / IP(src="203.0.113.10", dst="10.77.0.10") / TCP(flags="A")
    engine.packet(packet, Origin.REPLAY, "run")
    asset = engine.store.list("assets", {"source": "203.0.113.10"})["items"][0]
    assert asset["mac_observations"] == []
