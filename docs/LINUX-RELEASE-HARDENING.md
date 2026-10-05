> **Historical phase record.** Phase-specific approval/publication constraints below describe that completed phase. Current public-source status, Apache-2.0 license and verification are recorded in [PUBLICATION](PUBLICATION.md) and the [README](../README.md). Installer Linux lifecycle acceptance remains pending.

# Final Linux deployment hardening — 2026-10-05

## A. Verdict

**NOT READY FOR GITHUB publication yet.** Requested source hardening and installer implementation are complete for review. Contributor/institution/license rights remain unresolved, and the **new installer** needs fresh owned Ubuntu execution. The supplied manual Ubuntu/VMware runtime acceptance is real, documented and no longer described as wholly unverified. It does not certify new installer lifecycle behavior. No Git initialization, commit, push, tag, release or remote deployment was performed. Work was performed solo.

## B. Files changed

Modified:

- `netshield/helper.py`, `netshield/lab.py`: old-nft omitted-comment compatibility and text command output.
- `tests/test_helper.py`: eight compatibility regression cases.
- `deploy/netshield-web.service`, `deploy/netshield-maintenance.service`: AF_NETLINK, explicit empty ambient capabilities and isolated Python imports.
- `deploy/netshield-capture.service`, `deploy/netshield-helper.service`: isolated Python imports; helper explicitly empty ambient capabilities, bounding set unchanged.
- `setup.py`: fresh temporary build tree prevents stale retired modules leaking into wheels; existing build artifacts preserved.
- `.gitignore`, `scripts/publication_check.py`: private/runtime/TLS/build exclusions and canonical installer publication candidate.
- `.github/workflows/quality.yml`: prepared Linux Bash/ShellCheck checks; hosted workflow not executed.
- `README.md`, `docs/INSTALL.md`, `docs/RESPONSE.md`, `docs/NETSHIELD-V2-COMPLETION.md`: installer and correctly attributed acceptance.
- `docs/NETSHIELD-CURRENT-STATE.md`: only machine-specific absolute archive/workspace paths removed for publication hygiene; historical audit findings retained.

Added:

- `install.sh`, `scripts/linux_install.py`, `tests/test_linux_install.py`.
- `deploy/netshield-proxy.service`.
- `docs/LINUX-INSTALL.md`, `docs/LINUX-ACCEPTANCE.md`, this report.
- `docs/assets/linux-acceptance/{login,live-overview,scan-detection,ping-enforcement,response-applied,response-removed}.png` and `evidence-manifest.json`.

Approved frontend templates, CSS, JavaScript, SVG identity, detection engine and database model were not redesigned. Original `netshield.db` and `logs/netshield.log` remain byte-identical to the before snapshot. No source files were deleted.

## C. Acceptance fixes ported

Missing nft JSON comment now triggers only fixed table text inspection for the exact **table-level** marker; present wrong JSON comment refuses immediately. Nested/foreign/substring/second-table markers are denied. Full owned set/chain/rule/timeout schema validation remains intact. Both root and isolated-namespace nft runners preserve non-JSON output.

Web and maintenance permit AF_NETLINK for safe infrastructure discovery while retaining no capabilities. Capture remains CAP_NET_RAW only; helper root remains CAP_NET_ADMIN + CAP_CHOWN only. Python service entry points now use `-I`, preventing imports from writable data directories/PYTHONPATH. Installed-wheel QA proved this by placing a deliberately failing shadow module in the working directory.

## D. Installer experience and safety

Run `sudo bash install.sh` for prompts. Modes: interactive, explicit non-interactive network flags with secure deferred operator creation, read-only dry-run, and read-only verify-only. Optional hostname, provided TLS cert/key, explicit supported interpreter, explicitly approved Jammy PPA and opt-in manual response/private scope. [Full guide](LINUX-INSTALL.md).

The installer builds a reviewed wheel, installs a root-owned versioned runtime behind `/opt/netshield/venv`, resolves the nologin account's real UID/GID, creates private state and root-owned configs, initializes as netshield, invokes secure getpass bootstrap, installs six units, generates dedicated selected-IP Nginx TLS/ACL, and verifies the actual deployment.

Existing Nginx sites/defaults remain untouched. Foreign directories/files/symlinks/listeners/table ownership and modified managed files are refused. Reruns preserve config, operator/database records and certificates; identical files stay untouched, intentional unit updates get private backups, old runtimes are retained. Changed unprotected infrastructure is refused. Existing manual deployments without the ledger are **not adopted**. No automatic attack/block, forwarding/VMware/networking change, firewall reset or data purge. Explicit helper startup creates only its exact owned table.

This is not transactional apt/database/service rollback. Failures may require administrator recovery or ownership review; no evidence is erased to retry. Certificate renewal and manual-deployment migration require separately reviewed maintenance. A fresh VM should accept the automation before it is used to replace the already accepted manual deployment.

## E. Tests and build evidence

Executed locally on Windows / Python 3.14.6:

| Command/check | Result |
|---|---|
| `python -m pytest -q` | **122 passed, 1 skipped in 58.86s**; explicit Linux-only gate skipped |
| `python -m pytest tests/test_helper.py tests/test_linux_install.py -q` | **28 passed** |
| `python -m ruff check netshield scripts tests/test_*.py dashboard/app.py setup.py` | PASS |
| `python -m ruff format --check netshield scripts tests/test_*.py dashboard/app.py setup.py` | PASS, 43 files |
| `bash -n install.sh` (Git Bash) and `bash install.sh --help` | PASS |
| Local ShellCheck | Unavailable; prepared CI installs it if needed and runs it, not executed here |
| Bootstrap script AST with Python 3.10 syntax grammar | PASS; not actual Python 3.10 execution |
| `python -m pip wheel --no-deps --wheel-dir .workbench/linux-release-qa/rebuilt-wheels .` | PASS after build isolation fix |
| Fresh private venv → `pip install <rebuilt-wheel>` → `pip check` | PASS |
| Installed wheel from outside checkout, Python `-I`, hostile shadow working-directory module | PASS; installed imports only |
| Installed `init`, all authored replay scenarios, repeated init | **33/33 PASS**, no network transmission, retained evidence |
| Installed unauthenticated UI/API/local asset probes | Login redirect, API401, asset200 |
| Wheel contents | Retired dashboard API/models and V1 engines absent; no DB/private key/log/PCAP |
| Changed-line whitespace / original state hash checks | PASS; no deletions; original DB/log unchanged |
| Publication candidate hygiene and relative doc links | PASS; see local manifest and final review evidence |
| `git status --short` / Git diff | Not available: this workspace has no Git metadata; status returns “not a git repository” |

Final wheel: `netshield_ndr-2.0.0rc1-py3-none-any.whl`, **106,726 bytes**, SHA256 `e3a71c2642bc00632ab091113b07949e09fcf2980c5d097df4804a2f1aceac61`.

An initial `--no-build-isolation` attempt lacked local setuptools and failed; standard isolated build resolved that. The first resulting wheel then failed the strict contents probe because an old workspace build tree contained retired modules. It was rejected, the root cause fixed without deleting old artifacts, and a rebuilt wheel passed. Rejected/intermediate artifacts remain private under ignored QA storage. They are not release candidates.

Private evidence lives under ignored `.workbench/linux-release-qa/`: `wheel-evidence.json`, `publication-manifest.json`, `source-diff.json`, `source-diff.patch` and `final-review.json`. These are local review aids, not hosted CI or new Linux runtime evidence. Portable cases increased from the previous local 102 by eight nft regressions and twelve installer cases. The supplied VM's historical **104 passed, 1 skipped** is a different run/copy.

## F. Security boundaries

Web: unprivileged/no capabilities, loopback only. Capture: unprivileged/CAP_NET_RAW only. Helper: explicit opt-in/root/bounded NET_ADMIN+CHOWN, root-owned policy/code, restricted socket and independent SO_PEERCRED UID. Maintenance: no capabilities. Proxy: dedicated selected-IP TLS listener, bounded Nginx master privileges and unprivileged workers. NoNewPrivileges and isolated imports retained. Root-owned deployment files, restrictive TLS key mode, service-readable but non-writable config, private writable state, and dynamic UID/GID.

No default credentials or password arguments. Generated key/config/policy live outside the repository; private build/QA files are excluded. Acceptance IPs appear only in labelled documentation; no acceptance-machine IP or UID is a production default. Installer never claims enforcement from a request; verified helper readback remains authoritative. Default-off manual response and replay host-helper denial remain intact.

Verification checks actual process UID/capabilities, unit family/sandbox settings, real listeners, TLS identity/key/expiry and local ACL expectation, backend login redirect, durable capture heartbeat and strict helper schema/socket/peer list. Local TLS403 is expected when sensor IP is not allowlisted; actual allowed/denied remote client tests remain separate. Read-only helper operations do not add/remove blocks. Heartbeat is not full coverage or packet-loss proof.

## G. Documentation and supplied acceptance

[Acceptance record](LINUX-ACCEPTANCE.md) preserves the operator-reported Ubuntu 22.04.5 / Python 3.12.15 / nftables 1.0.2 namespace/live scan/manual enforcement/TTL/reconciliation/service/ACL results. Six images are byte-identical to the supplied originals. Counter **56 packets/4704 bytes** comes from the handoff; ping **112/56/50% loss** and APPLIED/REMOVED states are visible in supplied screenshots. No missing evidence was manufactured.

[Install guide](LINUX-INSTALL.md) documents flags, safe defaults, dynamic policies, explicit [Jammy Python3.10](https://packages.ubuntu.com/jammy/python3)/[Noble Python3.12](https://packages.ubuntu.com/noble/python3) branch and optional third-party trust choice. PPA package retrieval was not tested here. README, response and completion records distinguish supplied manual acceptance from new installer acceptance. Completion-document mojibake was corrected. Approved UI remains unchanged.

## H. Genuine remaining limits

- New installer/systemd proxy/first-install/rerun/failure lifecycle needs actual owned Ubuntu acceptance. Ubuntu24.04, IPv6 TLS and PPA dependency paths are targets/render-tested paths, not accepted deployments.
- Contributor/institution/license rights and dependency/asset notice review remain open; Apache-2.0 is only a recommendation.
- Hosted CI was prepared, not run. Local ShellCheck is unavailable.
- Existing manual deployment needs reviewed migration; no automatic adoption, purge or transactional rollback.
- Self-signed trust/renewal and real external client ACL tests remain operator tasks; raw screenshots include browser/VM chrome and need publication review.
- Prior application limits remain: metadata/placement boundaries, unknown kernel loss, bounded single-host SQLite/Python scale, no enterprise certification. No new features were added to disguise these limits.

## I. Diff and hygiene

There is no current Git diff/status/tracking proof because `.git` is absent. A complete before snapshot/hash manifest and unified file patch were created privately instead: **16 modified files, 14 added files (including six images), zero deletions**. Final changed/new file list is in `source-diff.json`; this document enumerates its scope. No rewritten frontend, changed original DB/log or new live traffic/firewall action on this workstation.

Review covered compatibility markers/schema, installer command arrays and privilege boundaries, every unit, wheel contents, all documentation deltas and six unaltered images. Root-only deployment/backup/certificate data, generated venv/build/dist/cache/DB/logs and local QA are excluded from publication candidates. **234 candidates** total approximately 11 MB, including intentionally documented images. No literal private key, QA credential, machine-specific production IP/UID or Windows absolute path was found in curated source. Pattern scans are not a guarantee or contributor-rights approval.

## J. Next Git commands — for Yousef, not executed

Only after rights/installer acceptance and explicit later authorization, from the source root in PowerShell:

```powershell
python scripts/publication_check.py --output .workbench/review-publication.json
git init --initial-branch=main
git remote add origin https://github.com/YousefE1bana/Net-Shield.git
$netshieldPaths = (Get-Content .workbench/review-publication.json -Raw | ConvertFrom-Json).files.path
foreach ($netshieldPath in $netshieldPaths) {
    git add -- $netshieldPath
}
git update-index --chmod=+x install.sh scripts/install-observe.sh
git diff --cached --check
git diff --cached --stat
git diff --cached
git status --short
```

Before staging, inspect the refreshed manifest and add only the owner-approved LICENSE/notices/package metadata after rights are settled; the generator deliberately does not invent these. Stop if hygiene is FAIL. These commands prepare a reviewable staging area; they contain no commit/push/tag/release. Never use blanket staging of the original private/V1 workspace. If a Git checkout is created separately before then, do not blindly rerun init/remote-add; inspect its identity first.

Implementation stops here for review.
