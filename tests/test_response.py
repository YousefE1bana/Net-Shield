import pytest
from netshield.response import Response
from netshield.settings import Settings
from netshield.store import Store


class KernelDouble:
    def __init__(self):
        self.elements = set()
        self.calls = []
        self.fail = False

    def request(self, operation, target="", ttl=0):
        self.calls.append(operation)
        if self.fail:
            raise OSError("helper unavailable")
        if operation == "add":
            self.elements.add(target)
        if operation == "remove":
            self.elements.discard(target)
        return {"targets": sorted(self.elements), "backend": "nftables", "scope": "test-double"}


def setup(tmp_path, origin="capture", enabled=True):
    store = Store(tmp_path / "test.db")
    settings = Settings(
        data_dir=tmp_path,
        response_enabled=enabled,
        response_networks=("10.77.0.0/24",),
        protected_networks=("10.77.0.1/32",),
    )
    alert = store.put(
        "alerts", {"origin": origin, "response_eligible": True, "source_ip": "10.77.0.2", "status": "OPEN"}
    )
    backend = KernelDouble()
    return Response(store, settings, backend), alert, backend


def test_replay_dry_run_never_calls_kernel(tmp_path):
    response, alert, backend = setup(tmp_path, "replay")
    with pytest.raises(ValueError):
        response.request(alert["id"], 120, "Reviewed evidence", "analyst")
    item = response.request(alert["id"], 120, "Reviewed evidence", "analyst", dry_run=True)
    assert not backend.calls and item["status"] == "VALIDATED"
    assert item["verification"] == "not_enforced"


def test_verified_apply_idempotency_and_removal(tmp_path):
    response, alert, backend = setup(tmp_path)
    first = response.request(alert["id"], 120, "Reviewed evidence", "analyst")
    assert first["status"] == "APPLIED" and first["verification"] == "kernel_present"
    assert response.request(alert["id"], 120, "Reviewed again", "analyst")["id"] == first["id"]
    removed = response.remove(first["id"], "analyst")
    assert removed["status"] == "REMOVED" and removed["verification"] == "kernel_absent"
    assert backend.calls.count("add") == 1


def test_protection_and_helper_loss_fail_closed(tmp_path):
    response, alert, backend = setup(tmp_path)
    alert["source_ip"] = "10.77.0.1"
    response.store.put("alerts", alert)
    with pytest.raises(ValueError):
        response.request(alert["id"], 120, "Reason", "analyst")
    assert not backend.calls
    alert["source_ip"] = "10.77.0.2"
    response.store.put("alerts", alert)
    backend.fail = True
    result = response.request(alert["id"], 120, "Reason", "analyst")
    assert result["status"] == "UNKNOWN"
    assert result["verification"] == "unavailable"


def test_expiry_needs_kernel_absence(tmp_path):
    response, alert, backend = setup(tmp_path)
    item = response.request(alert["id"], 60, "Reason", "analyst")
    item["expires_at"] = 0
    response.store.put("actions", item)
    backend.elements.clear()
    response.reconcile()
    assert response.store.get("actions", item["id"])["status"] == "REMOVED"
