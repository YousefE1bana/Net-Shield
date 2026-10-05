# Controlled Linux acceptance — 2026-10-05

This record attributes the **operator-supplied acceptance handoff and six screenshots**. The Windows implementation workstation did not rerun Linux systemd/nftables/capture tests. Screenshots are copied unchanged, with byte hashes in [evidence manifest](assets/linux-acceptance/evidence-manifest.json). Text-only command results below come from the handoff, not invented screenshot content. This is a controlled VMware home lab, **not enterprise/production certification**.

## Environment and evidence

| Component | Accepted environment |
|---|---|
| Sensor | Ubuntu 22.04.5 LTS, Python 3.12.15, nftables 1.0.2 |
| Sensor lab address / capture | 192.168.100.20 / ens34 |
| Owned Kali test VM | 192.168.100.10 |
| Windows management host | 192.168.100.1 |
| Management | Selected-IP Nginx HTTPS:443 → 127.0.0.1:8080, self-signed SAN certificate |

These are acceptance addresses, not generic defaults.

| Acceptance check | Reported outcome | Evidence scope |
|---|---|---|
| Portable suite on accepted VM | **104 passed, 1 skipped** | Operator handoff; historical VM copy after fixes |
| Explicit owned namespace closed loop | **PASS** | Operator handoff; separate from host-helper test |
| Real cross-VM scan detection | **PASS** | Nmap/dashboard screenshot and supplied rule details |
| Vertical scan | NS-RECON-VERTICAL v2.0.0, HIGH, observed 18 / threshold 15 over 30s | Operator detail; scan screenshot shows alert label/severity |
| Additional enumeration indicator | NS-RECON-ENUM | Operator detail and second alert visible in screenshot |
| Manual host response | **APPLIED / kernel_present**, Kali .10 target, finite 60s TTL | Response drawer screenshot and operator handoff |
| Kernel enforcement counter | **56 packets / 4704 bytes** dropped | Operator-supplied nft result; not separately visible in supplied screenshots |
| Connectivity during/after finite block | 112 transmitted / 56 received / 50% loss; connectivity restored after expiry | Ping summary screenshot + reported restoration |
| Kernel timeout removal | **PASS**; empty timeout set after expiry | Operator-supplied kernel readback |
| Durable reconciliation | **REMOVED / kernel_absent** | Response table screenshot |
| Maintenance | **status=0/SUCCESS**, timer active | Operator-supplied systemd results |
| Management client ACL | Windows allowed; Kali **HTTP 403** | Operator handoff; browser screenshot confirms selected-IP HTTPS access |
| Peer/privilege boundary | Student cannot access socket; root UID0 peer denied; dynamic netshield UID list permitted | Operator-supplied tests |

The login image shows the console login UI; its cropped frame alone does not show HTTPS transport. The response screenshot shows `kernel_present`, which is narrower than packet-path proof; counter and ping evidence supply the latter in this particular host path. Browser screenshots include the operator's normal browser/VM chrome and were not cropped or altered. The operator authorized publication of these supplied images.

## Screenshots

![Accepted live overview on ens34](assets/linux-acceptance/live-overview.png)

![Owned Kali scan and observed NetShield alerts](assets/linux-acceptance/scan-detection.png)

![Applied manual response with kernel presence and finite expiry](assets/linux-acceptance/response-applied.png)

![Ping loss summary during finite enforcement](assets/linux-acceptance/ping-enforcement.png)

![Response reconciled as removed with kernel absence](assets/linux-acceptance/response-removed.png)

[Unaltered login screenshot](assets/linux-acceptance/login.png).

## Fixes ported back to the reviewed source

1. nftables 1.0.x may omit table comments in JSON. Only when that field is absent, inspect fixed `nft list table inet netshield_v2` text and require the **exact table-level ownership marker**. Nested/substring/foreign markers are refused. An explicit wrong JSON marker is never overridden. All existing owned set/chain/rule/finite-timeout checks remain required.
2. The general nft command runner and isolated namespace runner preserve non-JSON stdout for that fallback.
3. Web and maintenance units permit **AF_NETLINK** for safe iproute2 infrastructure discovery while keeping empty capability sets. Capture stays CAP_NET_RAW only; helper stays CAP_NET_ADMIN + CAP_CHOWN only.

The new installer deploys these source fixes. Portable regressions verify their contracts; they are not another actual nftables 1.0.2 execution.

## New installer acceptance still needed

The manual architecture has real controlled-lab acceptance. The newly created `install.sh` automation, dedicated proxy unit, ownership ledger and runtime-switch flow have **not** run on an owned Linux VM yet. Do not treat the above results as installer acceptance.

Use a fresh owned Ubuntu VM, preserve existing accepted manual deployment, then retain evidence for:

- First install, observe-only helper inactivity, authenticated management access and actual privilege/listener boundaries.
- Same-choice rerun preserving operator/database/certificate, verify-only without evidence/rule mutations, and runtime update behavior.
- Explicit manual-helper opt-in, strict owned table readback, allowed/denied peers, external allowed/denied client ACLs.
- Foreign resources/listeners, edited config, missing venv support, certificate mismatch/expiry, apt/pip interruption and nginx validation failure; preserve unrelated sites/firewall and data.
- Expected sensor freshness and maintenance behavior under the generated units.

The maintainer selected [Apache-2.0](LICENSE-DECISION.md) for public source. Hosted CI/version checks remain separate from privileged runtime acceptance. High-throughput capture, all network placements, sustained service recovery and universal firewall coexistence are not certified by this lab.
