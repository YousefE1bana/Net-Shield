import tempfile
import unittest
from pathlib import Path


class DurableBootstrap(unittest.TestCase):
    def test_fresh_store_persists_evidence_on_restart(self):
        from netshield.store import Store

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.db"
            event = Store(path).put("events", {"origin": "replay", "run_id": "fixture", "event_time": 10})
            self.assertEqual(Store(path).get("events", event["id"]), event)
