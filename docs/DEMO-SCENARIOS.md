# Reproducible SOC demonstrations

All commands below run offline, require no root and transmit no traffic. Install the reviewed package, initialize a fresh data directory, bootstrap an operator, then run `python -m netshield --data data replay SCENARIO`. Start `serve` against the same data path, select **Replay**, **All retained data**, and the returned run. Recorded event time is deliberately retained. Other deterministic indicators may fire alongside the named primary rule; inspect actual observed_rules instead of expecting exactly one finding.

For every positive row: observation enters the real normalizer/rules → threshold evidence and occurrence are persisted → alert appears → open its evidence drawer → inspect the deterministic endpoint/time incident → record an attributable decision/note → use **dry run only** for eligible replay evidence → confirm not_enforced → resolve when appropriate → export the linked incident PDF/JSON. Zero findings do not establish safety. Benign controls produce no incident to export; do not manufacture one.

| Walkthrough / trigger | Observation → detection | Evidence → UI investigation → incident | Analyst decision / response | Verification → report |
|---|---|---|---|---|
| 1. `port-scan`: 18 distinct ports | Authored TCP initial packets → NS-RECON-VERTICAL (15/30s), enumeration may also fire | Distinct ports/window/samples + conversations; alert → endpoint/time incident | Acknowledge; label authorized validation; optional finite manual dry-run decision | Real PASS assertion; dry run never applied; resolve and export |
| 2. `horizontal-scan`, then `host-sweep` | 12 same-service destinations /12 ICMP echo targets → NS-RECON-HORIZONTAL /NS-RECON-SWEEP | Host count and target samples, run-scoped traffic/alerts; incidents reflect actual endpoint grouping | Review discovery permission; do not infer open services/host identity | Each fixed assertion PASS; export each actual linked incident |
| 3. `ssh-failures` | Seven authored failure-outcome events → NS-AUTH-SSH (5/60s) | Failure outcomes/service port; service events may have no packet flow; open alert/incident | Contrast `ssh-connections` (connection indicator only); note trusted-outcome requirement; replay dry run only | Check distinct semantics/real counts; incident PDF labels REPLAY |
| 4. `syn-rate` |105 initial SYN packets → NS-RATE-SYN (100/10s), target/service aggregation | Observed count/window and spoofable-source caveat; related traffic | Availability investigation, no automatic block; source attribution is insufficient for response eligibility | PASS does not prove service denial; evidence report retains caveat |
| 5. `http-surge` |55 whole cleartext requests fitting packets → NS-RATE-HTTP (50/10s) | Exact whole-request condition; no TLS/TCP-reassembly claim | Review `benign-http` ten-request negative control; no inferred encrypted request count | PASS /negative PASS independently; export positive incident |
| 6. `arp-conflict` |Two segment-scoped IP/MAC replies → NS-L2-ARP-CONFLICT | Competing binding values/interface, observed asset conflict; possible spoofing indicator | Investigate failover/address reuse; **no IP-block eligibility** | PASS verifies anomaly, not MITM; report binding evidence/limits |
| 7. `dns-subdomains`, `dns-long`, `dns-entropy` |Authored DNS queries → distinct-name/length/entropy indicators | Query hashes, length/entropy/parent context, no full payload storage | Review `benign-dns`; do not claim tunneling/exfiltration confirmed | Actual deterministic assertions and bounded evidence report |
| 8. `beacon` |Eight recorded outbound initial connections at regular intervals → NS-BEHAVIOR-BEACON | Interval samples, mean/median, jitter coefficient; conversations → incident | Compare scheduled automation; add scoped expiring exception if explained | PASS verifies timing indicator only; PDF notes no C2 conclusion |
| 9. `lateral-fanout`, `lateral-smb`, `lateral-rdp` |Internal SSH fan-out /14 repeated445 or3389 initial connections → NS-LATERAL-FANOUT /SERVICE | Internal addresses/port/count; network connections, no authentication/session proof | Review authorized administration; label addresses separately from device identity | Each PASS; export real incidents with qualified lateral-style language |
| 10. `benign-scanner`; explained positive scan |Eight ports → no findings; a larger authorized scan can legitimately fire | Negative control has no incident; inspect an actual `port-scan` finding for tuning | Add source+origin+rule expiring exception with reason; retain historical alert. Protect response targets separately | Re-run: suppression audit/evidence retained; positive fixture assertion can become FAIL under tuning, truthfully. Revoke exception, rerun to restore detection; export original incident |
| 11. `sensor-failure` |Authored operational replay event → NS-OPS-FAILURE | Component/state, replay alert → incident; Health still reports actual live capture separately | Review coverage, no blocking | PASS validates rule only, not a real outage; report clearly labels replay. Maintenance detects actual stale capture heartbeats separately |
| 12. `helper-failure` |Authored helper operational event → NS-OPS-FAILURE | Failure reason and replay evidence → incident | Record coverage issue; no host helper call | Replay PASS is not actual helper failure injection. Broker/helper contract tests separately verify UNKNOWN/unavailable on real-call failure; export operational replay incident |
| 13. Full closed loop |`python scripts/replay_demo.py --data data --output reports/demo-1` |18 packets →2 rules → occurrence/flow links → incident; acknowledged alert + notes | Manual60s dry-run decision, explicitly retired; resolve alert/incident | Actual PASS, REMOVED/not_enforced; local flagship-replay.pdf/json and result manifest |

## Flagship no-root demonstration

```mermaid
sequenceDiagram
  participant R as Authored offline replay
  participant P as Real parser and rules
  participant D as SQLite evidence
  participant A as Analyst console
  participant E as Local PDF/JSON
  R->>P: 18 timestamped initial packets (REPLAY)
  P->>D: Flows, occurrences, scan alert, incident
  D->>A: Exact ports/window, provenance and timeline
  A->>D: Acknowledge, note, manual dry-run decision
  Note over A,D: No helper/kernel call; not_enforced
  A->>D: Retire decision; resolve with validation note
  D->>E: Consistent bounded incident snapshot
```

The actual artifact is [flagship-replay.pdf](assets/v2-final/flagship-replay.pdf) and [result manifest](assets/v2-final/flagship-result.json). Browser screenshots contain actual authored replay results, never production telemetry. A useful short video follows: run confirmation → PASS → Traffic → alert threshold → incident timeline → Response not_enforced → PDF. Keep mode/coverage visible.

## Optional live kernel demonstration

On an explicitly owned dedicated Linux VM, follow [Attack Lab](ATTACK-LAB.md), then run `sudo /absolute/venv/bin/python -m netshield --data /private/lab-data isolated-lab --authorize-owned-namespace`. The fixed runner creates two new unrouted namespaces and a disposable9090 service, captures at most300 packets/5s, generates18 bounded connections, runs the same detector with ISOLATED_LAB origin, verifies namespace-owned nft element + blocked connectivity, verifies60s TTL absence + restored connectivity, resolves and exports, then deletes only its created namespaces/links. Ctrl+C and SIGTERM enter cleanup. Failure/remaining resources produce INCOMPLETE. No host helper or external target is used.

The kernel gate is **implemented but not executed here**: this workstation is Windows and only Docker Desktop's managed WSL environment is available. Do not present the offline artifacts as proof of live nftables behavior. Run the opt-in Linux test on the owned VM and retain the report/run manifest and before/after unrelated-host-policy evidence before public live-support claims.
