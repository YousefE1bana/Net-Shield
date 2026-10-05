# Scenario catalogue

| ID | Category | Budget | Expected rule |
|---|---|---|---|
| port-scan | Reconnaissance | 18 | NS-RECON-VERTICAL |
| horizontal-scan | Reconnaissance | 12 | NS-RECON-HORIZONTAL |
| host-sweep | Reconnaissance | 12 | NS-RECON-SWEEP |
| syn-rate | Availability | 105 | NS-RATE-SYN |
| udp-surge | Availability | 205 | NS-RATE-UDP |
| icmp-surge | Availability | 55 | NS-RATE-ICMP |
| http-surge | Availability | 55 | NS-RATE-HTTP |
| ssh-connections | Connections | 10 | NS-CONN-SSH |
| ssh-failures | Authentication | 7 | NS-AUTH-SSH |
| web-failures | Authentication | 12 | NS-AUTH-WEB |
| arp-conflict | Layer 2 | 2 | NS-L2-ARP-CONFLICT |
| dns-rate | DNS | 45 | NS-DNS-RATE |
| dns-long | DNS | 1 | NS-DNS-LONG |
| dns-entropy | DNS | 1 | NS-DNS-ENTROPY |
| dns-subdomains | DNS | 22 | NS-DNS-SUBDOMAINS |
| dns-new-parent | DNS | 12 | NS-DNS-NEW-PARENT |
| beacon | Behavior | 10 | NS-BEHAVIOR-BEACON |
| egress-volume | Egress | 260 | NS-EGRESS-VOLUME |
| egress-new | Egress | 1 | NS-EGRESS-NEW |
| egress-service | Egress | 1 | NS-EGRESS-SERVICE |
| egress-fanout | Egress | 22 | NS-EGRESS-FANOUT |
| lateral-fanout | Lateral movement indicators | 12 | NS-LATERAL-FANOUT |
| lateral-service | Lateral movement indicators | 14 | NS-LATERAL-SERVICE |
| sensor-failure | Operations | 1 | NS-OPS-FAILURE |
| benign | Negative control | 6 | No findings |
| ipv6-scan | Reconnaissance | 18 | NS-RECON-VERTICAL |
| lateral-smb | Lateral movement indicators | 14 | NS-LATERAL-SERVICE |
| lateral-rdp | Lateral movement indicators | 14 | NS-LATERAL-SERVICE |
| helper-failure | Operations | 1 | NS-OPS-FAILURE |
| writer-failure | Operations | 1 | NS-OPS-FAILURE |
| benign-scanner | Negative control | 8 | No findings |
| benign-http | Negative control | 10 | No findings |
| benign-dns | Negative control | 24 | No findings |

All above are offline authored fixtures, version1.0.0, no transmitted traffic and no live firewall authority. PASS asserts configured expected rules, not attack impact. Any tuning can change expected outcomes. Service scenarios are outcome fixtures, not a real credential-guessing service run.

The additional CLI-only owned-namespace-scan is Linux root/explicit authorization only, fixed18attempts,300packet/5s capture and60s namespace TTL; actual Linux execution remains an unverified platform gate.
