# Threat model and trust boundaries

Assets: operator credentials/session tokens, observation metadata, durable evidence, host connectivity, root helper policy and package integrity. Adversaries: hostile observed packets, unauthenticated management clients, malicious replay artifacts, compromised low-privilege analysts and false-positive/spoofed addresses. Local root and the trusted producer/code deployment administrator are trusted; compromise of them is outside containment.

| Boundary | Defense | Remaining limit |
|---|---|---|
| Network packet → normalized metadata | No payload retention, bounded windows/state/queue, fragments excluded from transport hints | Scapy parsing and Python processing are not a hardened high-volume sensor; malformed traffic can degrade coverage |
| Replay → host response | Trusted ingress enum + run partitions + independent broker origin gate; no event-upload API | Local executable/package tampering defeats ingress trust |
| Browser → management | Loopback/Host restriction, server session, CSRF/Origin, role checks, literal SQL parameters, CSP/safe text | No MFA; TLS/reverse proxy is operator responsibility |
| Web account → kernel | Manual eligible live alert, protected CIDRs, finite TTL, interprocess lock, independent root scope/peer UID, fixed commands/readback | Compromised authorized web service can request in-scope actions; protect jump hosts in root policy |
| Writable data → root helper | Root-owned code/config; separate private state; no plugin or shell syntax | Shared writable executable tree would break this boundary and is forbidden |
| Kernel action → UI state | Owned-schema verification, actual presence/absence, UNKNOWN on helper failure, kernel expiry | Presence proves installed scoped rule, not global network outcome; live gate needs dedicated Linux tests |
| Evidence → PDF/browser | Local rendering, escaped text, bounded joins, no remote assets/credential fields | No signed tamper-proof forensic chain; local DB owner can alter state |

Rate indicators deliberately do not allow manual source blocks where source attribution is target-aggregated/uncertain. ARP-only findings have no IP response eligibility. Even individually eligible scan/auth evidence requires analyst review; an address is not an authenticated human/device identity.

First-seen baselines reset on bounded-state eviction/consumer restart. DNS parent is last-two-label grouping, not a public-suffix-aware registrable domain. Sensor quietness differs from stopped/stale/error. Operational events may be unavailable during storage failure; the API/service health must reflect the gap. No claim of zero packet loss or complete LAN coverage is made.

Use the isolated lab only on a dedicated owned Linux VM. Ctrl+C executes bounded child/resource cleanup; SIGKILL/host crash cannot guarantee cleanup. Recorded generated names support manual inspection of exactly owned resources. Never test privileged networking inside Docker Desktop's managed WSL kernel.
