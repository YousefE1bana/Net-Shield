# Public source verification — 2026-10-05

The maintainer authorized publication of the current NetShield source to `YousefE1bana/Net-Shield`, selected Apache-2.0 and authorized the supplied screenshots. This supersedes the no-commit/no-push and pending-license constraints in historical phase reports. Product behavior and the approved console are preserved. No GitHub Release or tag is part of this publication.

## Source and licensing

- The repository contains the supported V2 runtime, console, deployment templates, installer, tests and documentation. Retired V1 files remain local, outside Git and the wheel.
- The unmodified Apache-2.0 text is in [LICENSE](../LICENSE); wheel metadata declares `Apache-2.0` and packages that text. Dependencies retain their [own licenses](DEPENDENCIES.md).
- All six operator-provided [Linux screenshots](assets/linux-acceptance) match their recorded SHA256 hashes and remain unaltered. Curated offline screenshots/reports are labelled separately.
- Original databases/logs, real captures, keys/certificates, local configs, environments, caches, builds and temporary QA manifests are excluded. The original database's bytes are preserved.
- Publication uses a curated file inventory, staged-file review and secret/path checks. Pattern scans are a hygiene check, not a claim that every possible secret format can be identified.

## Fresh local checks

Publication workstation: Windows, Python 3.14.6. No live capture, attack generation or firewall operation ran here.

| Check | Result |
|---|---|
| Complete pytest suite | **122 passed, 1 skipped**; 83.45 seconds. Skip is the explicit privileged Linux gate. |
| Fresh public-only source export | **122 passed, 1 skipped**; 81.16 seconds, without private/V1 workspace artifacts |
| Ruff lint and format | PASS; 43 Python files already formatted |
| Native console and browser-test JavaScript syntax | PASS |
| Bash syntax and installer help | PASS; no installation executed |
| ShellCheck 0.11.0 | PASS for canonical installer and portable observe installer |
| Wheel build | PASS; Apache-2.0 metadata/text included; retired control modules and private files excluded |
| Fresh environment dependency check | PASS; exact runtime pins installed, `pip check` clean |
| Installed-wheel offline library | **33/33 PASS** outside checkout with isolated imports |
| Installed console boundaries | PASS; unauthenticated API denied, login redirect/form and packaged CSS/JS/branding served |
| README and local documentation links | Validated against the curated public file inventory, including screenshots |
| Screenshot integrity | **6/6** supplied images match their manifest hashes |
| Staged publication inventory | 233 reviewed files; exact allowlist match; secret/path checks and template asset references pass |

There is no product frontend build step. The native assets ship in the Python wheel. Raw QA logs, credentials, generated environments, test databases and package artifacts remain private.

## Hosted Windows portability correction

The first hosted run passed all four Linux Python jobs and exposed an environmental dependency in the IPv6/VLAN offline test on Windows: unspecified Ethernet MAC fields caused Scapy to resolve an unavailable local adapter. The fixture now supplies explicit locally administered MAC addresses, asserts their preservation and rejects interface lookup. A local failing-then-passing regression reproduced that boundary. This correction is confined to test inputs; production parsing and detection behavior are preserved. The latest commit's complete hosted results are visible in GitHub Actions.

## Linux evidence and remaining acceptance

The operator-supplied **Ubuntu 22.04.5 / Python 3.12.15 / nftables 1.0.2** VMware run demonstrated scan detection, a manual finite host block, expiry/removal, management ACLs and privilege boundaries. [Detailed acceptance and attribution](LINUX-ACCEPTANCE.md).

That run used the manual deployment and a historical VM source copy. It does **not** establish fresh acceptance of the new `install.sh` lifecycle. First install, identical rerun, verify-only, failure recovery, allowed/denied external clients and unrelated-resource preservation still need execution on fresh owned Ubuntu VMs. Ubuntu 24.04 is a target, not an accepted runtime claim. Hosted offline CI is separate from privileged Linux deployment evidence; its current results are available in the repository's Actions view.

This is a public source candidate (`2.0.0rc1`), not a claim of enterprise certification, universal firewall coexistence or high-throughput zero-loss capture.
