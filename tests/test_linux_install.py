"""Portable installer contract tests; no system services or networking are changed."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "linux_install", Path(__file__).parents[1] / "scripts/linux_install.py"
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def plan(**changes):
    values = dict(
        capture="eth1",
        management="10.77.0.20",
        clients=["10.77.0.1/32"],
        sensor="lab",
        hostname="",
        response=False,
        networks=[],
    )
    values.update(changes)
    return installer.validate_plan(
        values, [{"ifname": "eth1", "addr_info": [{"local": "10.77.0.20", "prefixlen": 24}]}]
    )


def test_management_and_capture_must_be_explicit_local_literals():
    for changes in (
        {"capture": "missing"},
        {"management": "0.0.0.0"},
        {"management": "10.77.0.99"},
        {"hostname": "bad; injection"},
        {"clients": ["0.0.0.0/0"]},
        {"capture": "eth1;whoami"},
        {"sensor": "bad\nvalue"},
    ):
        with pytest.raises(ValueError):
            plan(**changes)


def test_response_requires_explicit_scope_and_private_networks():
    with pytest.raises(ValueError):
        plan(response=True)
    with pytest.raises(ValueError):
        plan(response=True, networks=["8.8.8.0/24"])


def test_both_authorities_protect_discovered_infrastructure_and_clients():
    addresses = [
        {"ifname": "eth0", "addr_info": [{"local": "10.50.0.2", "prefixlen": 24}]},
        {"ifname": "eth1", "addr_info": [{"local": "10.77.0.20", "prefixlen": 24}]},
    ]
    protected = installer.protections(plan(), addresses, [{"gateway": "10.50.0.1"}], ["10.50.0.53"])
    config, policy = installer.configurations(plan(), protected, 1234, 4321)
    assert config["protected_networks"] == policy["protected_networks"]
    assert {
        "10.50.0.0/24",
        "10.50.0.2/32",
        "10.50.0.1/32",
        "10.50.0.53/32",
        "10.77.0.20/32",
        "10.77.0.1/32",
    } <= set(protected)
    assert not config["auto_response"] and not config["response_enabled"]
    assert config["host"] == "127.0.0.1" and config["secure_cookie"]
    assert policy["client_uid"] == 1234 and policy["client_gid"] == 4321


def test_proxy_preserves_external_host_and_has_no_wildcard_or_foreign_site_changes():
    rendered = installer.nginx_config(plan())
    assert "listen 10.77.0.20:443 ssl" in rendered
    assert "proxy_set_header Host $host" in rendered
    assert "proxy_set_header X-Forwarded-Proto https" in rendered
    assert "allow 10.77.0.1/32;" in rendered and "deny all;" in rendered
    assert "TLSv1.2 TLSv1.3" in rendered
    assert "sites-enabled" not in rendered and "0.0.0.0" not in rendered


def test_ipv6_proxy_uses_bracketed_literal():
    values = dict(
        capture="eth1",
        management="fd77::20",
        clients=["fd77::1/128"],
        sensor="lab",
        hostname="console.lab",
        response=False,
        networks=[],
    )
    validated = installer.validate_plan(
        values, [{"ifname": "eth1", "addr_info": [{"local": "fd77::20", "prefixlen": 64}]}]
    )
    assert "listen [fd77::20]:443 ssl" in installer.nginx_config(validated)


def test_managed_update_preserves_backup_and_refuses_operator_changes(tmp_path):
    target = tmp_path / "unit"
    ledger = installer.ManagedFiles(tmp_path / "state.json", privileged=False)
    ledger.write(target, b"first", 0o640)
    ledger.write(target, b"second", 0o640)
    assert target.read_bytes() == b"second"
    assert next(tmp_path.glob("unit.*.bak")).read_bytes() == b"first"
    target.write_bytes(b"operator change")
    with pytest.raises(ValueError, match="modified"):
        ledger.write(target, b"third", 0o640)
    assert target.read_bytes() == b"operator change"


def test_foreign_file_and_symlink_are_never_adopted(tmp_path):
    target = tmp_path / "foreign"
    target.write_text("original")
    ledger = installer.ManagedFiles(tmp_path / "state.json", privileged=False)
    with pytest.raises(ValueError, match="Foreign"):
        ledger.write(target, b"new", 0o640)
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Host has no symlink permission")
    with pytest.raises(ValueError, match="symlink"):
        ledger.write(link, b"new", 0o640)
    assert target.read_text() == "original"


def test_ledger_persists_and_same_content_rerun_does_not_create_backup(tmp_path):
    target = tmp_path / "config.json"
    ledger = installer.ManagedFiles(tmp_path / "state.json", privileged=False)
    ledger.write(target, b"{}", 0o640)
    installer.ManagedFiles(ledger.path, privileged=False).write(target, b"{}", 0o640)
    assert not list(tmp_path.glob("*.bak"))
    assert json.loads(ledger.path.read_text())["files"][str(target)]


def test_verify_only_dispatch_never_discovers_installs_or_creates_state(monkeypatch, tmp_path):
    install_command = installer.install
    ledger = installer.ManagedFiles(tmp_path / "absent-state.json", privileged=False)
    ledger.state["plan"] = plan()
    monkeypatch.setattr(sys, "argv", ["linux_install.py", "--verify-only"])
    monkeypatch.setattr(installer, "platform_preflight", lambda: "22.04")
    monkeypatch.setattr(installer, "ManagedFiles", lambda: ledger)
    monkeypatch.setattr(installer, "resources_preflight", lambda _: None)
    monkeypatch.setattr(installer, "check_account", lambda: None)
    monkeypatch.setattr(installer, "verify", lambda _: True)
    monkeypatch.setattr(installer, "discover", lambda: pytest.fail("Verify must not discover/change config"))
    monkeypatch.setattr(installer, "install", lambda *_: pytest.fail("Verify must not install"))
    assert installer.main() == 0
    assert not ledger.path.exists()
    # A previously skipped operator must not unexpectedly prompt on unattended rerun.
    with pytest.raises(ValueError, match="skip-operator"):
        install_command(
            SimpleNamespace(non_interactive=True, skip_operator=False),
            ledger.state["plan"],
            ledger,
            "22.04",
            ([], [], []),
        )


def test_dry_run_dispatch_never_installs_or_writes(monkeypatch, tmp_path):
    ledger = installer.ManagedFiles(tmp_path / "absent-state.json", privileged=False)
    monkeypatch.setattr(sys, "argv", ["linux_install.py", "--dry-run"])
    monkeypatch.setattr(installer, "platform_preflight", lambda: "22.04")
    monkeypatch.setattr(installer, "ManagedFiles", lambda: ledger)
    monkeypatch.setattr(installer, "resources_preflight", lambda _: None)
    monkeypatch.setattr(installer, "check_account", lambda: None)
    monkeypatch.setattr(installer, "discover", lambda: ([], [], []))
    monkeypatch.setattr(installer, "select_plan", lambda *_: plan())
    monkeypatch.setattr(installer, "install", lambda *_: pytest.fail("Dry-run must not install"))
    assert installer.main() == 0
    assert not ledger.path.exists()


def test_foreign_listeners_fail_before_mutation(monkeypatch, tmp_path):
    ledger = installer.ManagedFiles(tmp_path / "state.json", privileged=False)
    for endpoint in ("0.0.0.0:443", "127.0.0.1:8080", "10.77.0.20:443"):
        monkeypatch.setattr(
            installer, "run", lambda *_: f'LISTEN 0 128 {endpoint} *:* users:(("other",pid=12,fd=3))'
        )
        with pytest.raises(ValueError, match="listener"):
            installer.listener_preflight(plan(), ledger)
    assert not ledger.path.exists()


def test_real_openssl_san_mismatch_and_certificate_reuse(tmp_path, monkeypatch):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL unavailable; no certificate verification claim")
    original = installer.run
    monkeypatch.setattr(
        installer,
        "run",
        lambda args, capture=True: original([openssl, *args[1:]] if args[0] == "openssl" else args, capture),
    )
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=console.lab",
            "-addext",
            "subjectAltName=IP:10.77.0.20,DNS:console.lab",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    original_bytes = key.read_bytes(), cert.read_bytes()
    installer.validate_certificate(cert, key, plan())
    installer.validate_certificate(cert, key, plan(hostname="console.lab"))
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        installer.validate_certificate(cert, key, {**plan(), "management": "10.77.0.99"})
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        installer.validate_certificate(cert, key, plan(hostname="other.lab"))
    assert original_bytes == (key.read_bytes(), cert.read_bytes())
