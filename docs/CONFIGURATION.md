# Configuration reference

Pass a local JSON path with `--config`; unknown keys, invalid types/CIDRs and non-loopback binds fail closed. `--data` explicitly overrides data_dir/database. `NETSHIELD_DATA` is the default directory only when JSON/CLI does not supply one. Configuration never grants provenance to an API caller.

| Setting | Default / bounds | Purpose |
|---|---|---|
| data_dir / database | data / data/netshield.db | Private persistent state; use absolute service paths |
| host / port | 127.0.0.1 / 8080; 1–65535 | Loopback management only |
| secure_cookie / trusted_hosts | false / localhost,127.0.0.1,::1 | Local HTTP or explicit TLS proxy policy |
| interface / sensor_id | empty / local | Linux literal interface, 1–64 character sensor ID |
| internal_networks | RFC1918 and fd00::/8 | Behavioral internal/external classification, not an authorization boundary |
| approved_outbound_ports | 53,80,123,443; 1–64 ports in1–65535 | Explicit outbound service baseline, not firewall policy |
| response_enabled / auto_response | false / false | Explicit manual enablement; true auto_response is rejected |
| response_networks | empty | App-level live response CIDR scope |
| protected_networks | loopback/link-local | App-level protection; helper policy is independent |
| helper_socket | /run/netshield/response.sock | Narrow Unix control boundary |
| queue_capacity | 2048; 16–65536 | Raw queue limit |
| state_capacity | 4096; 64–65536 | Rule/window/SYN keys; each window ≤512 observations |
| event_retention_days | 7; 1–365 | Raw events, flows and buckets by ingestion time |
| evidence_retention_days | 90; 7–3650 | Alerts, incidents, runs, audit and retired actions |
| flow_idle_seconds | 60; 5–3600 | Bidirectional conversation idle split |

Admin browser settings store typed retention values, applied by `maintenance --prune`/`retention`. Rule configuration permits finite threshold/window/enabled overrides only, generates a new rule version, and preserves old evidence. Count/byte thresholds are integral, rule samples ≤512, windows 1–86400s; volume ≤16MiB and entropy ≤8 bits/character. Fixed one-event semantics cannot be changed. New replay runs adopt immediately; capture/service consumers require restart. The outbound service indicator uses approved_outbound_ports, a typed local configuration of 1–64 integer ports (default53/80/123/443); consumers adopt on restart.

Detection exceptions require a known rule, explicit origin, source or target, owner/reason and 60–86400s expiry; revoke preserves historical evidence. Response-protected CIDRs are a separate admin object. Removing an app protection never changes root helper protections. No shell, nft syntax, interface start/stop, public target or auto-response toggle is exposed in browser settings.
