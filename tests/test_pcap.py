import pytest
from netshield.replay import Replay, write_fixture
from netshield.settings import Settings
from netshield.store import Store


def test_export_import_real_pcap_preserves_time_and_no_live_authority(tmp_path):
    path = tmp_path / "scan.pcap"
    write_fixture("port-scan", path)
    settings = Settings(data_dir=tmp_path)
    store = Store(settings.database)
    run = Replay(store, settings).import_pcap(path, "test")
    assert run["status"] == "COMPLETE" and run["processed"] == 18
    alerts = store.list("alerts", {"run": run["id"], "rule": "NS-RECON-VERTICAL"})["items"]
    assert alerts and alerts[0]["origin"] == "replay" and alerts[0]["first_seen"] < 1700000002
    assert store.list("actions")["total"] == 0


def test_pcap_cap_does_not_claim_complete(tmp_path):
    path = tmp_path / "scan.pcap"
    write_fixture("port-scan", path)
    settings = Settings(data_dir=tmp_path)
    runner = Replay(Store(settings.database), settings)
    result = runner.import_pcap(path, "test", max_packets=2)
    assert result["status"] == "INCOMPLETE" and result["processed"] == 2


def test_pcap_corruption_and_overwrite_are_refused(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"Not a capture")
    settings = Settings(data_dir=tmp_path)
    runner = Replay(Store(settings.database), settings)
    assert runner.import_pcap(path, "test")["status"] == "INCOMPLETE"
    with pytest.raises(ValueError):
        write_fixture("port-scan", path)
