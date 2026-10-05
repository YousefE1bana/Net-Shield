import pytest
from scapy.all import IP, TCP
from netshield.pipeline import Pipeline
from netshield.events import Origin
from netshield.store import Store
from netshield.settings import Settings


def test_tuning_versions_evidence_and_is_not_response_permission(tmp_path):
    store = Store(tmp_path / "test.db")
    store.put(
        "settings",
        {"id": "rule-overrides", "overrides": {"NS-RECON-VERTICAL": {"threshold": 3, "window": 5}}},
    )
    pipeline = Pipeline(store, Settings(data_dir=tmp_path))
    for index in range(3):
        packet = IP(src="10.77.0.2", dst="10.77.0.10") / TCP(
            sport=40000 + index, dport=8000 + index, flags="S", seq=index
        )
        packet.time = 100 + index
        pipeline.packet(packet, Origin.REPLAY, "tuned")
    alert = store.list("alerts")["items"][0]
    assert alert["rule_id"] == "NS-RECON-VERTICAL"
    assert alert["evidence"]["threshold"] == 3 and alert["evidence"]["window_seconds"] == 5
    assert alert["rule_version"] != "2.0.0"
    assert store.list("protections")["total"] == 0


@pytest.mark.parametrize(
    "config",
    [
        {"MISSING": {"threshold": 3}},
        {"NS-RATE-SYN": {"threshold": -2}},
        {"NS-RATE-SYN": {"window": float("nan")}},
        {"NS-RATE-SYN": {"enabled": "yes"}},
    ],
)
def test_invalid_tuning_is_refused(config):
    from netshield.rules import configured

    with pytest.raises(ValueError):
        configured(config)
