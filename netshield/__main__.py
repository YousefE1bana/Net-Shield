"""Local administration; secrets enter through getpass, never command arguments."""

import argparse
from dataclasses import replace
import getpass
import json
from pathlib import Path
import signal
from .settings import Settings
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="NetShield local operations")
    parser.add_argument("--config", help="Local JSON configuration")
    parser.add_argument("--data", help="Explicit data directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Initialize/migrate with automatic pre-migration backup")
    operator = sub.add_parser("operator-add")
    operator.add_argument("username")
    operator.add_argument("--role", choices=("admin", "operator", "viewer"), default="admin")
    sub.add_parser("serve", help="Unprivileged authenticated loopback management")
    sub.add_parser("capture", help="Observe only on locally configured interface; no firewall authority")
    ssh = sub.add_parser("ssh-events", help="Trusted local sshd journal failed-password outcomes (Linux)")
    ssh.add_argument("--local-address", required=True, help="Observed local sshd address")
    web_events = sub.add_parser("web-events", help="Bounded root-owned trusted local web service JSONL spool")
    web_events.add_argument("path")
    replay = sub.add_parser("replay")
    replay.add_argument("scenario", nargs="?", default="port-scan")
    replay.add_argument("--all", action="store_true")
    pcap = sub.add_parser("import-pcap")
    pcap.add_argument("path")
    fixture = sub.add_parser("fixture")
    fixture.add_argument("scenario")
    fixture.add_argument("output")
    report = sub.add_parser("report")
    report.add_argument("incident")
    report.add_argument("output")
    report.add_argument("--format", choices=("json", "pdf"), default="pdf")
    backup = sub.add_parser("backup")
    backup.add_argument("output")
    sub.add_parser("retention")
    sub.add_parser("reconcile")
    maintenance = sub.add_parser(
        "maintenance", help="Sensor staleness, response reconciliation, optional retention"
    )
    maintenance.add_argument("--prune", action="store_true")
    lab = sub.add_parser(
        "isolated-lab", help="Explicit owned Linux namespace scan/kernel TTL demo; no external targets"
    )
    lab.add_argument("--authorize-owned-namespace", action="store_true")
    helper = sub.add_parser("helper")
    helper.add_argument("policy")
    args = parser.parse_args()
    if args.command == "helper":
        from .helper import serve_helper

        serve_helper(args.policy)
        return
    settings = Settings.load(args.config)
    if args.data:
        settings = replace(settings, data_dir=Path(args.data), database=Path(args.data) / "netshield.db")
    store = Store(settings.database)
    if args.command == "init":
        print(json.dumps({"database": str(store.path), "schema_version": 2, "mode": "observe-only"}))
    elif args.command == "operator-add":
        password = getpass.getpass("New operator password (12+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            raise ValueError("Password confirmation differs")
        store.create_operator(args.username, password, args.role)
        print("Operator created. No default password exists.")
    elif args.command == "serve":
        from waitress import serve
        from .web import create_app

        serve(create_app(settings), host=settings.host, port=settings.port, threads=4)
    elif args.command == "ssh-events":
        from .services import observe_ssh
        from .pipeline import Pipeline

        observe_ssh(Pipeline(store, settings), args.local_address)
    elif args.command == "web-events":
        from .services import import_web_events
        from .pipeline import Pipeline

        print(json.dumps(import_web_events(Pipeline(store, settings), args.path)))
    elif args.command == "capture":
        from .capture import Intake
        from .pipeline import Pipeline

        intake = Intake(Pipeline(store, settings))
        intake.start()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: intake.stop_event.set())
        try:
            while not intake.stop_event.wait(1):
                pass
        finally:
            print(json.dumps(intake.stop()))
    elif args.command in ("replay", "import-pcap"):
        from .replay import Replay, SCENARIOS

        runner = Replay(store, settings)
        if args.command == "import-pcap":
            results = [runner.import_pcap(args.path, "local-cli")]
        else:
            results = [runner.run(name, "local-cli") for name in (SCENARIOS if args.all else [args.scenario])]
        print(json.dumps(results, indent=2))
        if any(r["status"] not in ("PASS", "COMPLETE") for r in results):
            raise SystemExit(1)
    elif args.command == "fixture":
        from .replay import write_fixture

        write_fixture(args.scenario, args.output)
        print("Authored offline PCAP written; no packets transmitted.")
    elif args.command == "report":
        from .reports import Reports

        output = Path(args.output)
        if output.exists():
            raise ValueError("Report output must be a new file")
        reports = Reports(store)
        snapshot = reports.snapshot(args.incident)
        output.write_bytes(reports.pdf(snapshot) if args.format == "pdf" else reports.json(snapshot))
        store.audit("local-cli", "incident.exported", args.incident, "success", format=args.format)
        print(str(output.resolve()))
    elif args.command == "backup":
        print(str(store.backup(args.output)))
    elif args.command == "retention":
        effective = store.get("settings", "effective") or {}
        print(
            json.dumps(
                store.prune(
                    effective.get("event_retention_days", settings.event_retention_days),
                    effective.get("evidence_retention_days", settings.evidence_retention_days),
                )
            )
        )
    elif args.command == "reconcile":
        from .response import Response

        Response(store, settings).reconcile()
        print("Response states reconciled against available helper evidence.")
    elif args.command == "isolated-lab":
        # Termination follows the same owned-resource cleanup path as Ctrl+C.
        def cancel_owned_lab(*_):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, cancel_owned_lab)
        from .lab import run_lab

        result = run_lab(store, settings, args.authorize_owned_namespace)
        print(json.dumps(result, indent=2))
        if result["status"] != "PASS":
            raise SystemExit(1)
    elif args.command == "maintenance":
        from .maintenance import maintain

        print(json.dumps(maintain(store, settings, args.prune)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
