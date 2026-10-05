"""Reproducible no-root investigation, manual dry-run decision and SOC exports."""

import argparse
import json
from pathlib import Path
from netshield.investigations import Investigations
from netshield.replay import Replay
from netshield.reports import Reports
from netshield.response import Response
from netshield.settings import Settings
from netshield.store import Store


def run(data, output):
    settings = Settings(data_dir=Path(data))
    store = Store(settings.database)
    replay = Replay(store, settings).run("port-scan", "local-demo")
    if replay["status"] != "PASS":
        raise ValueError("Port-scan assertion failed")
    alert = store.list("alerts", {"run": replay["id"], "rule": "NS-RECON-VERTICAL"}, limit=1)["items"][0]
    investigation = Investigations(store, settings)
    investigation.change(
        "alerts",
        alert["id"],
        {"status": "ACKNOWLEDGED", "note": "Authorized offline fixture. Distinct-port evidence reviewed."},
        "local-demo",
    )
    broker = Response(store, settings)
    action = broker.request(
        alert["id"], 60, "Replay response review: no firewall authority", "local-demo", dry_run=True
    )
    broker.remove(action["id"], "local-demo")
    linked = store.get("incidents", alert["incident_id"])["alert_ids"]
    for identity in linked:
        investigation.change(
            "alerts",
            identity,
            {"status": "RESOLVED", "note": "Related indicator reviewed as authorized offline validation."},
            "local-demo",
        )
    incident = investigation.change(
        "incidents",
        alert["incident_id"],
        {
            "status": "RESOLVED",
            "note": "Controlled replay validation completed. Dry-run decision retired manually. No kernel enforcement was attempted or verified.",
        },
        "local-demo",
    )
    reports = Reports(store)
    snapshot = reports.snapshot(incident["id"])
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for suffix, content in (("json", reports.json(snapshot)), ("pdf", reports.pdf(snapshot))):
        with (output / ("flagship-replay." + suffix)).open("xb") as file:
            file.write(content)
    result = {
        "result": "PASS",
        "scope": "offline replay; no network/firewall calls",
        "run_id": replay["id"],
        "incident_id": incident["id"],
        "packets": replay["processed"],
        "observed_rules": replay["observed_rules"],
        "response": "REMOVED / not_enforced",
        "report": str(output / "flagship-replay.pdf"),
    }
    (output / "flagship-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    run(args.data, args.output)
