# Detection catalogue

Rules are deterministic indicators, not confirmed attacks. Defaults below are generated from the implemented catalogue. All rules accept trusted ingress origins capture/service_event/replay/isolated_lab; response authority is checked separately. All confidence values are deliberately indicator.

| Rule | Name / category | Threshold / window | Severity | Manual response |
|---|---|---|---|---|
| NS-RECON-VERTICAL | Vertical port scan indicator / Reconnaissance | 15 distinct ports / 30s | HIGH | True |
| NS-RECON-HORIZONTAL | Horizontal service scan indicator / Reconnaissance | 10 distinct hosts / 30s | HIGH | True |
| NS-RECON-SWEEP | Host discovery sweep indicator / Reconnaissance | 10 distinct hosts / 30s | MEDIUM | False |
| NS-RECON-ENUM | Service enumeration pattern / Reconnaissance | 10 distinct ports / 60s | MEDIUM | False |
| NS-RATE-SYN | SYN rate anomaly / Availability | 100 initial SYNs/window / 10s | HIGH | False |
| NS-RATE-UDP | UDP surge indicator / Availability | 200 packets/window / 10s | MEDIUM | False |
| NS-RATE-ICMP | ICMP surge indicator / Availability | 50 packets/window / 10s | MEDIUM | False |
| NS-RATE-HTTP | HTTP request surge / Availability | 50 complete requests/window / 10s | MEDIUM | False |
| NS-CONN-SSH | Repeated SSH connection attempts / Connections | 8 initial SYNs/window / 60s | MEDIUM | False |
| NS-AUTH-SSH | Repeated failed SSH authentication / Authentication | 5 failed outcomes/window / 60s | HIGH | True |
| NS-AUTH-WEB | Repeated failed web authentication / Authentication | 10 failed outcomes/window / 60s | HIGH | True |
| NS-L2-ARP-CONFLICT | ARP binding conflict / Layer 2 | 2 competing MAC claims / 300s | MEDIUM | False |
| NS-DNS-RATE | DNS query-rate anomaly / DNS | 40 queries/window / 10s | MEDIUM | False |
| NS-DNS-LONG | Long DNS query indicator / DNS | 100 name characters / 60s | MEDIUM | False |
| NS-DNS-ENTROPY | Tunneling-like DNS label indicator / DNS | 4 Shannon bits/character / 60s | MEDIUM | False |
| NS-DNS-SUBDOMAINS | Distinct DNS subdomain burst / DNS | 20 distinct query hashes / 60s | MEDIUM | False |
| NS-DNS-NEW-PARENT | Repeated newly observed DNS parent / DNS | 10 queries/window / 60s | LOW | False |
| NS-BEHAVIOR-BEACON | Periodic outbound beaconing indicator / Behavior | 8 connection observations / 3600s | MEDIUM | False |
| NS-EGRESS-VOLUME | Large outbound transfer indicator / Egress | 1048576 observed bytes/window / 60s | MEDIUM | False |
| NS-EGRESS-NEW | New external destination observation / Egress | 1 first connection / 3600s | LOW | False |
| NS-EGRESS-SERVICE | Unexpected outbound service indicator / Egress | 1 connection / 60s | MEDIUM | False |
| NS-EGRESS-FANOUT | Rapid destination fan-out / Egress | 20 distinct external hosts / 60s | MEDIUM | False |
| NS-LATERAL-FANOUT | Internal lateral-movement-style fan-out / Lateral indicators | 10 distinct internal hosts / 60s | MEDIUM | False |
| NS-LATERAL-SERVICE | Repeated internal administration connections / Lateral indicators | 12 initial connections/window / 60s | MEDIUM | False |
| NS-OPS-FAILURE | Operational coverage failure / Operations | 1 failure event / 60s | HIGH | False |

## NS-RECON-VERTICAL — Vertical port scan indicator

Initial SYNs from one source to distinct ports on one destination.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `port-scan, ipv6-scan`. Version `2.0.0`.
ATT&CK: T1046 — Network service probing; legitimate scanners may match.. [Primary reference](https://attack.mitre.org/techniques/T1046/), reviewed 2026-10-04.

## NS-RECON-HORIZONTAL — Horizontal service scan indicator

One source probes one service across distinct destinations.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `horizontal-scan`. Version `2.0.0`.
ATT&CK: T1046 — Service probing across hosts; no compromise inference.. [Primary reference](https://attack.mitre.org/techniques/T1046/), reviewed 2026-10-04.

## NS-RECON-SWEEP — Host discovery sweep indicator

ICMP echo requests to many destinations.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `host-sweep`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-RECON-ENUM — Service enumeration pattern

Repeated initial connections to multiple service ports; service identity unknown.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `Related engine boundary tests`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-RATE-SYN — SYN rate anomaly

Target-aggregated initial SYN count with source attribution uncertainty.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `syn-rate`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-RATE-UDP — UDP surge indicator

Target/service-aggregated UDP packet count.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `udp-surge`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-RATE-ICMP — ICMP surge indicator

Target-aggregated ICMP packet burst; impact not measured.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `icmp-surge`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-RATE-HTTP — HTTP request surge

Complete one-packet plaintext requests or trusted HTTP service events; no HTTPS guessing.

Evidence: Complete observable HTTP request or trusted request event. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `http-surge`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-CONN-SSH — Repeated SSH connection attempts

Connections to port 22, not authentication outcomes.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `ssh-connections`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-AUTH-SSH — Repeated failed SSH authentication

Trusted failed authentication events; credentials never retained.

Evidence: Trusted sshd failed-auth outcome. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `ssh-failures`. Version `2.0.0`.
ATT&CK: T1110.001 — Repeated failed password-authentication outcomes; guessing indicator.. [Primary reference](https://attack.mitre.org/techniques/T1110/001/), reviewed 2026-10-04.

## NS-AUTH-WEB — Repeated failed web authentication

Trusted application failed-login events.

Evidence: Trusted application authentication outcome. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `web-failures`. Version `2.0.0`.
ATT&CK: T1110.001 — Failed application login sequence; no confirmed credential access.. [Primary reference](https://attack.mitre.org/techniques/T1110/001/), reviewed 2026-10-04.

## NS-L2-ARP-CONFLICT — ARP binding conflict

Competing IP-to-MAC claims within the same interface/VLAN and recent baseline.

Evidence: Normalized packet metadata. Benign causes: DHCP reassignment, VRRP/failover, deliberate network maintenance. Fixture: `arp-conflict`. Version `2.0.0`.
ATT&CK: T1557.002 — ARP binding anomaly relevant to poisoning; does not establish interception.. [Primary reference](https://attack.mitre.org/techniques/T1557/002/), reviewed 2026-10-04.

## NS-DNS-RATE — DNS query-rate anomaly

Observed DNS query burst per source.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `dns-rate`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-DNS-LONG — Long DNS query indicator

Unusually long observable DNS name; no exfiltration proof.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `dns-long`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-DNS-ENTROPY — Tunneling-like DNS label indicator

First label length at least 32 and entropy at least threshold.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `dns-entropy`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-DNS-SUBDOMAINS — Distinct DNS subdomain burst

Many distinct names under the same observed last-two-label parent; public suffix not inferred.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `dns-subdomains`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-DNS-NEW-PARENT — Repeated newly observed DNS parent

Repeated queries to a parent first seen in this process/run; persistence coverage limited.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `dns-new-parent`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-BEHAVIOR-BEACON — Periodic outbound beaconing indicator

At least eight outbound initial connections; mean interval >=2s, coefficient of variation <=0.10. Scheduled automation may match.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `beacon`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-EGRESS-VOLUME — Large outbound transfer indicator

Internal source to external destination exceeds configured fixed byte budget; no learned anomaly score.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `egress-volume`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-EGRESS-NEW — New external destination observation

First external destination in bounded process/run state. Observation, not maliciousness.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `egress-new`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-EGRESS-SERVICE — Unexpected outbound service indicator

External service outside configured approved outbound ports.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `egress-service`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-EGRESS-FANOUT — Rapid destination fan-out

Internal source opens connections to many external destinations.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `egress-fanout`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-LATERAL-FANOUT — Internal lateral-movement-style fan-out

One internal source probes SSH/SMB/RDP across internal hosts; lateral movement not confirmed.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `lateral-fanout`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-LATERAL-SERVICE — Repeated internal administration connections

Repeated internal SSH/SMB/RDP initial connections.

Evidence: Normalized packet metadata. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `lateral-service, lateral-smb, lateral-rdp`. Version `2.0.0`.
No ATT&CK mapping asserted.

## NS-OPS-FAILURE — Operational coverage failure

Trusted local sensor/writer/database/helper/queue failure or stopped/stale component.

Evidence: Trusted health event. Benign causes: Authorized scanning, automation or legitimate application activity. Fixture: `sensor-failure, helper-failure, writer-failure`. Version `2.0.0`.
No ATT&CK mapping asserted.

## Common correctness limits

SYN deduplication includes sensor/interface/VLAN/run and sequence/endpoint fingerprint over3s. Distinct-port/host thresholds use initial SYN observations, not confirmed service identity. Rate rules aggregate at target/service; packet addresses can be spoofed and these rules are not response eligible. SSH authentication requires failed outcomes from a trusted adapter, never a port22 SYN. HTTP counts complete one-packet plaintext requests on80/8080 or trusted service events; no reassembly/TLS parsing. Fragmented transport is excluded from protocol hints.

ARP claims are scoped by segment; old competing MACs expire from the rule window. An asset history conflict may remain visible after a legitimate rebinding. DNS analyzes observable UDP53 requests only; query hashes/length/entropy and parent survive, complete query names do not. First-seen DNS/egress state resets on process/run/eviction; DNS new-parent repetition applies only within its initial window. Approved outbound ports are53/80/123/443 in this implementation. Beacon intervals require mean>=2s, jitter coefficient<=0.10 and enough samples; scheduled automation can match. Large outbound volume is a fixed budget indicator, not learned anomaly or proof of exfiltration.

Configuration changes create a version suffix and affect new replay runs, with live consumers adopting on restart. Rule state is bounded, evictions/truncation visible. Late events persist but do not evaluate rolling windows. Historical versions/occurrences remain evidence.
