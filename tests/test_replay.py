import pytest
from netshield.replay import Replay, SCENARIOS
from netshield.settings import Settings
from netshield.store import Store


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_real_pipeline_scenario_assertions(tmp_path, scenario):
    store = Store(tmp_path / "test.db")
    runner = Replay(store, Settings(data_dir=tmp_path))
    result = runner.run(scenario, "test")
    assert result["status"] == "PASS"
    assert result["origin"] == "replay"
    assert result["processed"] == SCENARIOS[scenario]["budget"]
    assert store.list("actions")["total"] == 0
    assert result["detected_events"] == store.list("occurrences", {"run": result["id"]})["total"]
    if scenario == "benign":
        assert store.list("alerts", {"run": result["id"]})["total"] == 0


def test_unknown_scenario_and_unbounded_pcap_are_refused(tmp_path):
    runner = Replay(Store(tmp_path / "test.db"), Settings(data_dir=tmp_path))
    with pytest.raises(ValueError):
        runner.run("../../attack", "test")
    assert runner.store.list("lab_runs")["total"] == 0
