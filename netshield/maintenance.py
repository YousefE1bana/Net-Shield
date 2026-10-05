"""Bounded local periodic maintenance; no automatic response decisions."""

import time
from .events import Origin
from .pipeline import Pipeline
from .response import Response


def maintain(store, settings, prune=False):
    pipeline = None
    now = time.time()
    for sensor in store.list("sensors", limit=100)["items"]:
        if (
            sensor.get("origin") == "capture"
            and sensor.get("capture_state") == "running"
            and now - sensor.get("capture_heartbeat", 0) > 10
        ):
            pipeline = pipeline or Pipeline(store, settings)
            sensor.update(capture_state="stale", stale_observed_at=now)
            store.put("sensors", sensor)
            pipeline.service(
                {
                    "kind": "operational",
                    "component": "sensor-heartbeat",
                    "state": "stale",
                    "error_code": "heartbeat_over_10s",
                },
                Origin.SERVICE_EVENT,
            )
    broker = Response(store, settings)
    # Expire dry runs even when host enforcement is disabled. Foreign lab actions
    # are excluded by the broker's authority check.
    broker.reconcile()
    effective = store.get("settings", "effective") or {}
    counts = (
        store.prune(
            effective.get("event_retention_days", settings.event_retention_days),
            effective.get("evidence_retention_days", settings.evidence_retention_days),
        )
        if prune
        else {}
    )
    return {
        "status": "Completed against available dependencies",
        "retention": counts,
        "automatic_response": False,
    }
