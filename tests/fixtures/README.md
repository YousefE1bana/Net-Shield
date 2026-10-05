# Permissioned offline fixtures

port-scan.pcap is self-authored by NetShield `fixture port-scan`, not a private capture. It contains18 TCP initial packets between10.77.0.2 and10.77.0.10 at recorded fixture time, no credentials/payloads. Import through `python -m netshield --data data import-pcap tests/fixtures/port-scan.pcap`; no packets are sent. External PCAP import reports COMPLETE, not PASS, because it has no expected-detection assertion contract.

All other fixtures are authored lazily in netshield/replay.py with explicit manifests in docs/SCENARIOS.md. Never replace these with private/live captures. Licensing still requires the owner's public-release decision.
