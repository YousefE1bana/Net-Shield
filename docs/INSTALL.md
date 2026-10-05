# Installation and lifecycle

## Observe/replay installation

Use Python 3.11+, an unprivileged account and a fresh virtual environment. Windows and Linux replay need no capture privileges. Install `python -m pip install .` from this checkout, or `python -m pip install netshield_ndr-2.0.0rc1-py3-none-any.whl` from a locally built reviewed wheel. Runtime dependencies are exact pins in requirements.txt. A wheel packages the local console assets.

`scripts/install-observe.ps1` and `scripts/install-observe.sh` install into a **new** environment and initialize a new V2 data directory; they refuse to replace an existing environment, do not upgrade the OS, and do not alter firewall/networking. The retired root `setup.sh` exits without executing its historical body.

```sh
python -m netshield --data data init
python -m netshield --data data operator-add yousef
python -m netshield --data data replay --all
python -m netshield --data data serve
```

Password input is interactive getpass, 12–256 characters, no default password. Management binds only loopback. `config.example.json` is safe observe-only; copy to ignored `config.local.json`, then use `--config config.local.json` consistently on every process. Data paths are resolved against the working directory.

## Dedicated Linux deployment

The root-level **`install.sh`** is the canonical installer for new owned Ubuntu systemd VMs. It generates configuration, dynamic UID/GID helper policy, wheel-based immutable runtime, least-privilege units and selected-IP Nginx/TLS with management ACLs. Observe-only is default; manual helper startup is explicit opt-in. See the complete [Linux installer guide](LINUX-INSTALL.md) for prompts, flags, Python 3.11+ on Jammy, protections, verification, safe reruns and failure recovery.

```sh
sudo bash install.sh
sudo bash install.sh --dry-run
sudo bash install.sh --verify-only
```

The manually deployed Ubuntu 22.04.5/Python 3.12.15/nftables 1.0.2 VMware lab has operator-reported real acceptance. [Evidence and limits](LINUX-ACCEPTANCE.md). The **new installer itself has not run on Linux yet**; a fresh owned VM acceptance remains required. It refuses to adopt a pre-existing manual deployment without its ownership ledger. Do not delete the accepted VM's data/config to bypass that guard.

## Trusted service events

`ssh-events --local-address <literal-local-IP>` reads only root sshd journal records in ssh.service/sshd.service and retains failure outcomes without account names/passwords. Grant journal read access separately. No unit is installed automatically. `web-events /path/to/root-owned.jsonl` imports a trusted web producer's bounded root-owned regular spool; group/world writable files and symlinks are refused. Contract in API.md. A normal user-supplied file must use replay; do not relabel it trusted.

## Development and quality

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check netshield scripts tests/test_*.py dashboard/app.py
python -m ruff format --check netshield scripts tests/test_*.py dashboard/app.py
bash -n install.sh
shellcheck install.sh
node --check dashboard/static/js/v2-console.mjs
python scripts/benchmark.py reports/benchmark.json
```

Browser QA uses Playwright for development only, with private generated credentials; see tests/ui/README.md. Never put passwords into command arguments. No product JS build is required.

## Backup, upgrade, recover, uninstall

`python -m netshield --config config.local.json backup /new/private/backup.db` uses SQLite backup API and integrity_check; existing destinations are refused. Stop capture/ingestion and maintenance before upgrading. Back up first, install the reviewed new wheel into a **new root-owned environment**, run init, verify schema/backup integrity, bootstrap/session behavior and replay, then switch the root-owned active runtime link after review. The canonical installer retains previous runtimes but does not provide transactional OS/database rollback. Future/unknown DB schemas are rejected without erasing evidence. Restore a verified backup to a separate new data path while services are stopped; preserve old data until recovery is confirmed.

Uninstall means stop/disable the exact NetShield services/timer and archive the owned data/config/environment at chosen paths. Reconcile/remove active owned targets first; kernel TTLs expire even if the helper stops. The helper does not flush UFW/firewalld or any ruleset. If retiring the table, inspect its ownership marker/schema and delete only `inet netshield_v2` as a deliberate local admin action; no blanket firewall reset is provided. Do not delete unrelated namespaces, rules, files or captures.
