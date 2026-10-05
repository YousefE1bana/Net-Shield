"""Measured offline benchmark. Never opens capture or firewall services."""

import argparse
import json
import platform
import statistics
import tempfile
import time
import tracemalloc
from dataclasses import replace
from pathlib import Path
from scapy.all import Ether, IP, TCP
from netshield.events import Origin, normalize_packet
from netshield.pipeline import Pipeline
from netshield.rules import RuleEngine
from netshield.settings import Settings
from netshield.store import Store
from netshield.web import create_app
from netshield.capture import Intake


def measure(label, count, operation):
    tracemalloc.start()
    cpu = time.process_time()
    start = time.perf_counter()
    for index in range(count):
        operation(index)
    elapsed = time.perf_counter() - start
    used = time.process_time() - cpu
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "phase": label,
        "items": count,
        "wall_seconds": elapsed,
        "process_cpu_seconds": used,
        "items_per_second": count / elapsed,
        "python_peak_traced_bytes": peak,
    }


def benchmark():
    packets = []
    for i in range(2000):
        p = Ether() / IP(src="10.77.0.2", dst="10.77.0.10") / TCP(sport=40000 + i % 100, dport=443, flags="A")
        p.time = 1700000000 + i * 0.001
        packets.append(p)
    raw = [bytes(p) for p in packets]
    results = [
        measure(
            "Scapy decode + normalization",
            len(raw),
            lambda i: normalize_packet(Ether(raw[i]), Origin.REPLAY, "benchmark", "fixture", "parser"),
        )
    ]
    events = [normalize_packet(p, Origin.REPLAY, "benchmark", "fixture", "rules") for p in packets]
    engine = RuleEngine(Settings())
    results.append(
        measure(
            "Rule evaluation (benign ACK observations)", len(events), lambda i: engine.evaluate(events[i])
        )
    )
    pressure = RuleEngine(Settings())

    def evaluate_pressure(i):
        pressure.evaluate(
            replace(
                events[i],
                source_ip=f"10.1.{i // 250}.{i % 250 + 1}",
                metadata={"tcp_flags": 2, "tcp_sequence": i},
            )
        )

    results.append(
        measure("Rule state pressure (distinct initial connections)", len(events), evaluate_pressure)
    )
    state_pressure = {
        "keys": len(pressure.states),
        "syn_fingerprints": len(pressure.seen_syn),
        "evictions": pressure.evictions,
    }
    with tempfile.TemporaryDirectory(prefix="netshield-benchmark-") as directory:
        settings = Settings(data_dir=Path(directory))
        store = Store(settings.database)
        pipeline = Pipeline(store, settings)
        results.append(
            measure(
                "Pipeline + transactional SQLite persistence",
                500,
                lambda i: pipeline.packet(packets[i], Origin.REPLAY, "persistent", "fixture"),
            )
        )

        def persist_batch(index):
            with store.transaction():
                for i in range(index * 32, min(500, (index + 1) * 32)):
                    pipeline.packet(packets[i], Origin.REPLAY, "batched", "fixture")

        batch = measure("Pipeline + SQLite, consumer-sized batches", 16, persist_batch)
        batch.update(packets=500, packets_per_second=500 / batch["wall_seconds"], maximum_batch_packets=32)
        results.append(batch)
        intake = Intake(pipeline, capacity=128)
        for packet in packets[:260]:
            intake.offer(packet)
        queue = {
            "offered": intake.received,
            "retained": intake.queue.qsize(),
            "overflow": intake.overflows,
            "capacity": intake.queue.maxsize,
        }
        app = create_app(settings)
        store.create_operator("benchmark", "local-benchmark-only-password")
        client = app.test_client()
        csrf = client.get("/auth/session").json["csrf"]
        client.post(
            "/auth/login",
            json={"username": "benchmark", "password": "local-benchmark-only-password", "csrf": csrf},
        )
        latency = {}
        for endpoint in (
            "flows?origin=replay&limit=50",
            "overview?origin=replay",
            "alerts?origin=replay&limit=50",
        ):
            samples = []
            for _ in range(20):
                start = time.perf_counter()
                response = client.get("/api/v2/" + endpoint)
                samples.append((time.perf_counter() - start) * 1000)
                if response.status_code != 200:
                    raise ValueError("Benchmark request failed")
            latency[endpoint] = {
                "samples": len(samples),
                "median_ms": statistics.median(samples),
                "p95_ms": sorted(samples)[18],
            }
        db_bytes = sum(p.stat().st_size for p in Path(directory).glob("netshield.db*"))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": platform.processor(),
        "phases": results,
        "api_in_process": latency,
        "database_plus_wal_bytes_after_500_packets": db_bytes,
        "bounds": {
            "rule_keys": 4096,
            "window_samples": 512,
            "raw_queue": 2048,
            "metadata_record_bytes": 262144,
        },
        "state_pressure": state_pressure,
        "queue_pressure": queue,
        "limitations": [
            "Offline decoded/generated traffic only; these are not live capture PPS or packet-loss claims.",
            "tracemalloc records Python allocation peaks, not complete process RSS or native allocator use.",
            "API uses authenticated Flask test client; excludes TCP/TLS/proxy/Waitress network overhead.",
            "Single local execution under current workstation load; no sustained appliance throughput certification.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    args = parser.parse_args()
    result = benchmark()
    output = Path(args.output)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
