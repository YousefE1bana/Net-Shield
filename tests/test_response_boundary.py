import pytest
from tests.test_response import setup


def test_lab_state_never_calls_host_helper_for_removal_or_reconcile(tmp_path):
    broker, alert, kernel = setup(tmp_path, "isolated_lab")
    action = broker.store.put(
        "actions",
        {
            "origin": "isolated_lab",
            "run_id": "owned-lab",
            "target_ip": alert["source_ip"],
            "status": "APPLIED",
            "dry_run": False,
            "expires_at": 0,
            "history": [],
        },
    )
    with pytest.raises(ValueError):
        broker.remove(action["id"], "analyst")
    broker.reconcile()
    assert kernel.calls == []
    assert broker.store.get("actions", action["id"])["status"] == "APPLIED"
