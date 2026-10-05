import os
import platform
import json
import subprocess
import pytest
from netshield.lab import authorized, run_lab
from netshield.settings import Settings
from netshield.store import Store


def test_namespace_authorization_is_explicit():
    with pytest.raises(ValueError):
        authorized(False)


@pytest.mark.linux
@pytest.mark.skipif(
    platform.system() != "Linux" or os.environ.get("NETSHIELD_LINUX_TESTS") != "1",
    reason="Explicit operator-owned Linux VM kernel gate required",
)
def test_owned_namespace_kernel_closed_loop(tmp_path):
    assert os.geteuid() == 0, "Dedicated owned Linux VM root required"

    def host_policy():
        result = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "ruleset"], check=True, capture_output=True, text=True, timeout=5
        )

        def stable(value):
            if isinstance(value, dict):
                return {k: stable(v) for k, v in value.items() if k not in {"packets", "bytes", "expires"}}
            if isinstance(value, list):
                return [stable(v) for v in value]
            return value

        return stable(json.loads(result.stdout))

    before = host_policy()
    result = run_lab(Store(tmp_path / "lab.db"), Settings(data_dir=tmp_path), True)
    assert host_policy() == before, "Unrelated host firewall policy changed"
    assert result["status"] == "PASS", result
    assert result["cleanup_remaining"] == []
