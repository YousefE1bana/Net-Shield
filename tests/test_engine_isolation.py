from scapy.all import IP, TCP, UDP, DNS, DNSQR
from netshield.events import Origin, normalize_packet
from netshield.rules import RuleEngine, configured
from netshield.settings import Settings
import pytest


def event(packet, when, sensor="one"):
    packet.time = when
    return normalize_packet(packet, Origin.REPLAY, sensor, "fixture", "run")


def test_syn_retransmission_tracking_is_sensor_scoped():
    engine = RuleEngine(Settings(), {"NS-RECON-VERTICAL": {"threshold": 1}})
    packet = IP(src="10.77.0.2", dst="10.77.0.10") / TCP(sport=40000, dport=80, flags="S", seq=1)
    assert engine.evaluate(event(packet, 100, "one"))
    assert engine.evaluate(event(packet, 100, "two"))
    assert engine.evaluate(event(packet, 101, "two")) == []


def test_dns_new_parent_is_only_new_in_the_initial_window():
    engine = RuleEngine(Settings(), {"NS-DNS-NEW-PARENT": {"threshold": 2, "window": 10}})
    packet = IP(src="10.77.0.2", dst="10.77.0.10") / UDP(dport=53) / DNS(qd=DNSQR(qname="www.lab.test"))
    assert "NS-DNS-NEW-PARENT" not in {x["rule"].id for x in engine.evaluate(event(packet, 100))}
    assert "NS-DNS-NEW-PARENT" in {x["rule"].id for x in engine.evaluate(event(packet, 101))}
    for when in (120, 121):
        assert "NS-DNS-NEW-PARENT" not in {x["rule"].id for x in engine.evaluate(event(packet, when))}


def test_discrete_thresholds_cannot_be_fractional():
    with pytest.raises(ValueError):
        configured({"NS-RECON-VERTICAL": {"threshold": 1.5}})
