"""Bounded raw intake; DB/rules are only in the analysis consumer, never callback."""

from queue import Queue, Full, Empty
import threading
import time
from pathlib import Path
from scapy.all import sniff
from .events import Origin


class Intake:
    def __init__(self, pipeline, capacity=None, origin=Origin.CAPTURE, run_id="", interface=None):
        self.pipeline = pipeline
        self.queue = Queue(maxsize=capacity or pipeline.settings.queue_capacity)
        self.origin, self.run_id, self.interface = origin, run_id, interface or pipeline.settings.interface
        self.stop_event = threading.Event()
        self.worker = None
        self.capture_worker = None
        self.overflows = 0
        self.received = 0
        self.heartbeat = 0
        self.started = 0
        self.last_observation = None
        self.error = ""

    def offer(self, packet):
        self.received += 1
        try:
            self.queue.put_nowait(packet)
        except Full:
            self.overflows += 1

    def health(self):
        try:
            interface_state = (Path("/sys/class/net") / self.interface / "operstate").read_text().strip()
        except OSError:
            interface_state = "unknown"
        return {
            "interface_state": interface_state,
            "queue_size": self.queue.qsize(),
            "queue_capacity": self.queue.maxsize,
            "queue_overflow": self.overflows,
            "capture_received": self.received,
            "capture_heartbeat": self.heartbeat,
            "last_observation": self.last_observation,
            "parser_failures": self.pipeline.parser_failures,
            "writer_failures": self.pipeline.writer_failures,
            "kernel_packet_loss": "Unknown",
            "kernel_drop_count": None,
            "capture_state": "failed"
            if self.error
            else ("running" if self.heartbeat else "starting")
            if self.capture_worker and self.capture_worker.is_alive() and not self.stop_event.is_set()
            else "stopped",
            "interface": self.interface,
            "error_code": self.error,
            "event_time": time.time(),
            "id": self.pipeline.settings.sensor_id,
            "rule_state_evictions": self.pipeline.rules.evictions,
            "window_truncations": self.pipeline.rules.window_truncations,
        }

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        if not self.interface:
            raise ValueError("An explicitly approved capture interface is required")
        self.started = time.time()
        self.stop_event.clear()
        self.error = ""
        self.heartbeat = 0
        self.worker = threading.Thread(target=self.consume, name="netshield-analysis", daemon=True)
        self.capture_worker = threading.Thread(target=self.capture, name="netshield-capture", daemon=True)
        self.worker.start()
        self.capture_worker.start()

    def capture(self):
        try:
            # One-second windows make quiet-link cancellation/heartbeat observable.
            while not self.stop_event.is_set():
                sniff(iface=self.interface, store=False, prn=self.offer, timeout=1)
                self.heartbeat = time.time()
        except Exception as error:
            self.error = type(error).__name__
            self.stop_event.set()

    def consume(self):
        last_health = last_overflows = 0
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                packet = self.queue.get(timeout=0.2)
            except Empty:
                packet = None
            if packet is not None:
                batch = [packet]
                for _ in range(31):
                    try:
                        batch.append(self.queue.get_nowait())
                    except Empty:
                        break
                try:
                    # Amortize durable commits in the consumer, while keeping the
                    # raw callback non-blocking. Any writer error rolls back the
                    # whole batch and stops intake; never continue a partial write.
                    with self.pipeline.store.transaction():
                        for observation in batch:
                            self.pipeline.packet(observation, self.origin, self.run_id, self.interface)
                    self.last_observation = time.time()
                except Exception as error:
                    self.error = type(error).__name__
                    self.stop_event.set()
                finally:
                    for _ in batch:
                        self.queue.task_done()
            if time.time() - last_health >= 1:
                try:
                    self.pipeline.store.put("sensors", self.health())
                    if self.overflows > last_overflows:
                        self.pipeline.service(
                            {
                                "kind": "operational",
                                "component": "queue",
                                "state": "overflow",
                                "error_code": "bounded_intake_full",
                            },
                            self.origin,
                            self.run_id,
                        )
                        last_overflows = self.overflows
                    last_health = time.time()
                except Exception:
                    self.error = "WriterUnavailable"
        try:
            self.pipeline.store.put("sensors", self.health())
            if self.error:
                self.pipeline.service(
                    {
                        "kind": "operational",
                        "component": "capture",
                        "state": "failed",
                        "error_code": self.error,
                    },
                    self.origin,
                    self.run_id,
                )
        except Exception:
            self.error = "WriterUnavailable"

    def stop(self):
        self.stop_event.set()
        for worker in (self.capture_worker, self.worker):
            if worker:
                worker.join(timeout=3)
        return self.health()
