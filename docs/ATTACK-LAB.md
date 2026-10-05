# Controlled Attack Lab

The browser library is **offline replay only**. Named immutable fixture manifests define category, expected rule, observation budget, scenario version and duration. No target, URL, command or password-list input exists. Fixtures enter the actual normalizer and rule pipeline with recorded event time and fresh run partitions; they do not inject an alert. SHA256 describes the processed fixture sequence, not a forensic signature.

Replay permits one active job per local runner, at most 260 observations for a built-in scenario, 120s wall time and cancellation between observations. PCAP import is CLI-local, <=20MiB/5000 packets/120s, retains recorded time and provenance, and reports COMPLETE without pretending external expected assertions exist. Built-in scenario PASS requires all required detector assertions; benign fixtures assert no findings. Other observed rules are retained. Tuning/suppression can intentionally cause FAIL. Exceptions during processing are INCOMPLETE. Offline cleanup is explicitly not required because no networking resources were created.

Run `python -m netshield replay --all`, or choose an Attack Lab scenario → review target/budget/mode → confirm → inspect progress → expected/observed result → pivot to alerts/flows → investigation → dry-run response/report. Authentication fixtures contain trusted-outcome structures; they do not perform real password guessing.

## Optional owned Linux live gate

Prerequisites: dedicated operator-owned Linux VM, root for this one CLI action, Python environment with NetShield/Scapy, `/usr/sbin/ip` and `/usr/sbin/nft`. No external network route is created.

```sh
sudo /opt/netshield/venv/bin/python -m netshield --data /private/lab-data isolated-lab --authorize-owned-namespace
```

Fresh random `ns-a-*` and `ns-v-*` namespaces contain one owned veth pair, fixed addresses 10.77.0.2/10.77.0.10 and a disposable TCP9090 service. No default route, bridge to a physical NIC, forwarding/NAT setup or arbitrary target is accepted. Worker code refuses the host namespace. Fixed generation is 18 connect attempts to ports8000–8017, at most20 attempts/s, bounded 300-packet/5s capture, 120s execution budget and 60s namespace nft TTL. The real captured PCAP enters origin isolated_lab. Only that namespace's kernel state is changed.

Required assertions: baseline reachable → scan detector + flows + incident → explicit namespace block present → service unreachable → kernel TTL absence → service reachable → incident resolved → local PDF → owned child/ns/veth cleanup. Missing assertions/resources produce INCOMPLETE. Ctrl+C runs cleanup; kernel/host crash/SIGKILL requires inspection of recorded generated names. Namespace deletion destroys its private rules, preserving the host ruleset.

Run `NETSHIELD_LINUX_TESTS=1 sudo ... -m pytest tests/test_linux_lab.py -m linux` only after reviewing the code on that VM (pass the variable through sudo explicitly). The gate is skipped on Windows. A separate operator-supplied owned-VM namespace PASS is attributed in [Linux acceptance](LINUX-ACCEPTANCE.md); portable tests do not establish kernel enforcement. Live SSH/web password-failure service generation is not part of this small optional runner; trusted adapters and authored offline outcomes cover those indicators.
