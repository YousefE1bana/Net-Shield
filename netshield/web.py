"""Authenticated, bounded management. No packet/event injection or socket controls."""

from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
import secrets
import threading
import time
import shutil
import platform
import sqlite3
from .pipeline import Pipeline
from .investigations import Investigations
from .response import Response
from .replay import Replay, SCENARIOS
from .reports import Reports
from flask import Flask, g, jsonify, redirect, render_template, request, make_response
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from .settings import Settings
from .store import Store

COOKIE = "NS_session"


def body(required=(), allowed=()):
    value = request.get_json(silent=True)
    if not isinstance(value, dict) or not set(required) <= value.keys() or set(value) - set(allowed):
        raise ValueError("Expected a JSON object with the documented fields")
    return value


def authorize(role="operator"):
    def decorator(fn):
        @wraps(fn)
        def checked(*args, **kwargs):
            levels = {"viewer": 0, "operator": 1, "admin": 2}
            if not g.operator or levels[g.operator["role"]] < levels[role]:
                return jsonify(error="Permission denied"), 403
            return fn(*args, **kwargs)

        return checked

    return decorator


def create_app(settings=None):
    settings = settings or Settings.load()
    root = Path(__file__).resolve().parent.parent / "dashboard"
    app = Flask(__name__, template_folder=str(root / "templates"), static_folder=str(root / "static"))
    app.config.update(MAX_CONTENT_LENGTH=16384, TRUSTED_HOSTS=list(settings.trusted_hosts))
    store = Store(settings.database)
    Pipeline(store, settings)  # Seed actual versioned rule catalogue, never demo data.
    investigation = Investigations(store, settings)
    response_engine = Response(store, settings)
    replay = Replay(store, settings)
    reports = Reports(store)
    app.extensions.update(store=store, settings=settings, replay=replay, response=response_engine)
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")

    @app.before_request
    def management_boundary():
        # Validate Host even when a before-request denial short-circuits routing.
        request.host
        g.operator = store.session(request.cookies.get(COOKIE, ""))
        if request.path.startswith("/socket.io/"):
            return jsonify(error="SocketIO controls retired; use authenticated API V2"), 410
        if request.path.startswith("/api/") and not g.operator:
            return jsonify(error="Authentication required"), 401
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if origin and urlsplit(origin).netloc != request.host:
                return jsonify(error="Origin denied"), 403
            if request.path == "/auth/login":
                login_body = request.get_json(silent=True)
                supplied = login_body.get("csrf", "") if isinstance(login_body, dict) else ""
                token = request.cookies.get("NS_login_csrf", "")
            else:
                supplied = request.headers.get("X-CSRF-Token", "")
                token = g.operator["csrf"] if g.operator else ""
            if not isinstance(supplied, str) or not token or not secrets.compare_digest(supplied, token):
                return jsonify(error="CSRF token required"), 403

    @app.after_request
    def headers(response):
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        if settings.secure_cookie:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)[:160]), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    @app.errorhandler(sqlite3.DatabaseError)
    @app.errorhandler(OSError)
    def storage_unavailable(error):
        app.logger.error("Management dependency unavailable: %s", type(error).__name__)
        return jsonify(error="Local storage or system dependency unavailable; inspect service health"), 503

    @app.get("/auth/session")
    def session_info():
        if g.operator:
            return jsonify(g.operator)
        token = secrets.token_urlsafe(32)
        response = jsonify(username=None, csrf=token)
        response.set_cookie(
            "NS_login_csrf",
            token,
            secure=settings.secure_cookie,
            httponly=True,
            samesite="Strict",
            max_age=300,
        )
        return response

    @app.route("/auth/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", configured=bool(store.operators()))
        value = body(("username", "password", "csrf"), ("username", "password", "csrf"))
        if not store.login_allowed(request.remote_addr or "unknown"):
            response = jsonify(error="Login rate limit reached; retry in five minutes")
            response.headers["Retry-After"] = "300"
            return response, 429
        username, password = value["username"], value["password"]
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or len(username) > 32
            or len(password) > 256
        ):
            return jsonify(error="Invalid credentials"), 401
        password_hash = store.operator_hash(username)
        matches = check_password_hash(password_hash or dummy_hash, password)
        if not password_hash or not matches:
            store.audit("anonymous", "login.failed", "management", "denied")
            return jsonify(error="Invalid credentials"), 401
        token, csrf = store.start_session(username)
        store.audit(username, "login", "management", "success")
        response = jsonify(username=username, csrf=csrf)
        response.set_cookie(
            COOKIE, token, max_age=28800, secure=settings.secure_cookie, httponly=True, samesite="Strict"
        )
        response.delete_cookie("NS_login_csrf")
        return response

    @app.post("/auth/logout")
    def logout():
        store.end_session(request.cookies.get(COOKIE, ""))
        response = jsonify(status="logged_out")
        response.delete_cookie(COOKIE)
        return response

    @app.get("/")
    def console():
        if not g.operator:
            return redirect("/auth/login")
        return render_template(
            "index.html",
            console_context={
                "operator": g.operator["username"],
                "role": g.operator["role"],
                "csrf": g.operator["csrf"],
                "interface": settings.interface,
                "version": "2.0.0rc1",
            },
        )

    @app.get("/api/v2/status")
    def status():
        sensors = store.list("sensors", limit=100)["items"]
        now = time.time()
        for sensor in sensors:
            sensor["heartbeat_age_seconds"] = now - (sensor.get("capture_heartbeat") or sensor["event_time"])
            if sensor["heartbeat_age_seconds"] > 5 and sensor.get("capture_state") == "running":
                sensor["capture_state"] = "stale"
        capture = next((s for s in sensors if s.get("id") == settings.sensor_id), None)
        free = shutil.disk_usage(settings.data_dir).free
        return jsonify(
            mode="observe-only",
            automatic_response=False,
            live_capture=capture.get("capture_state", "unknown") if capture else "stopped",
            sensors=sensors,
            kernel_drop_count=capture.get("kernel_drop_count") if capture else None,
            interface=settings.interface or None,
            response_enabled=settings.response_enabled,
            database="readable",
            database_bytes=store.path.stat().st_size,
            disk_free_bytes=free,
            platform=platform.system(),
            schema_version=2,
            updated_at=now,
            coverage=[
                "Observation point determines visible traffic.",
                "No TLS decryption or TCP stream reassembly.",
                "Kernel drop count is unknown unless provided by capture backend.",
            ],
        )

    resources = {
        "events": "events",
        "flows": "flows",
        "metrics": "metrics",
        "alerts": "alerts",
        "occurrences": "occurrences",
        "incidents": "incidents",
        "incident-links": "incident_links",
        "assets": "assets",
        "bindings": "bindings",
        "rules": "rules",
        "actions": "actions",
        "exceptions": "exceptions",
        "protections": "protections",
        "audit": "audit",
        "lab-runs": "lab_runs",
        "sensors": "sensors",
    }

    @app.get("/api/v2/<resource>")
    def collection(resource):
        if resource == "overview":
            return jsonify(store.overview(request.args.to_dict()))
        if resource == "rule-config":
            return jsonify(
                overrides=(store.get("settings", "rule-overrides") or {}).get("overrides", {}),
                adoption="New replay runs use saved configuration; capture/service consumers adopt on restart.",
            )
        if resource == "scenarios":
            if request.args:
                raise ValueError("Scenario catalogue does not accept filters")
            return jsonify(items=[{"id": key, **value} for key, value in SCENARIOS.items()], schema_version=2)
        if resource == "settings":
            return jsonify(
                interface=settings.interface,
                internal_networks=settings.internal_networks,
                response_enabled=settings.response_enabled,
                automatic_response=False,
                response_networks=settings.response_networks,
                protected_networks=settings.protected_networks,
                event_retention_days=settings.event_retention_days,
                evidence_retention_days=settings.evidence_retention_days,
                saved=store.get("settings", "effective"),
                role=g.operator["role"],
                username=g.operator["username"],
            )
        if resource not in resources:
            return jsonify(error="Resource not found"), 404
        query = request.args.to_dict()
        limit, offset = query.pop("limit", 50), query.pop("offset", 0)
        result = store.list(resources[resource], query, limit=limit, offset=offset)
        if resource == "rules":
            with store.connection() as conn:
                statistics = {
                    (row["rule_id"], row["version"]): dict(row)
                    for row in conn.execute(
                        "SELECT rule_id,json_extract(body,'$.rule_version') AS version,"
                        "COUNT(*) AS alert_count,MAX(event_time) AS last_triggered "
                        "FROM v2_alerts GROUP BY rule_id,version"
                    )
                }
            for item in result["items"]:
                measured = statistics.get((item["rule_id"], item["version"]), {})
                item.update(
                    alert_count=measured.get("alert_count", 0),
                    last_triggered=measured.get("last_triggered"),
                    statistics_scope="All retained origins, exact rule version",
                )
        return jsonify(result)

    @app.get("/api/v2/incidents/<identity>/evidence")
    def incident_evidence(identity):
        if request.args:
            raise ValueError("Incident evidence does not accept filters")
        snapshot = reports.snapshot(identity)
        snapshot["occurrences"] = snapshot["occurrences"][-100:]
        return jsonify(snapshot)

    @app.get("/api/v2/<resource>/<identity>")
    def detail(resource, identity):
        if resource not in resources:
            return jsonify(error="Resource not found"), 404
        item = store.get(resources[resource], identity)
        if not item:
            return jsonify(error="Resource not found"), 404
        return jsonify(item)

    @app.patch("/api/v2/<resource>/<identity>")
    @authorize()
    def analyst_update(resource, identity):
        return jsonify(
            investigation.change(
                resource, identity, body((), ("status", "note", "label")), g.operator["username"]
            )
        )

    @app.post("/api/v2/incidents/<identity>/detach")
    @authorize()
    def detach(identity):
        value = body(("alert_id", "reason"), ("alert_id", "reason"))
        return jsonify(
            investigation.detach(identity, value["alert_id"], value["reason"], g.operator["username"])
        )

    @app.post("/api/v2/exceptions")
    @authorize()
    def add_exception():
        value = body(
            ("rule_id", "origin", "duration", "reason"),
            ("rule_id", "origin", "duration", "reason", "source_ip", "target_ip", "sensor_id"),
        )
        return jsonify(investigation.exception(value, g.operator["username"])), 201

    @app.post("/api/v2/exceptions/<identity>/revoke")
    @authorize()
    def revoke_exception(identity):
        body((), ())
        return jsonify(investigation.revoke(identity, g.operator["username"]))

    @app.post("/api/v2/protections")
    @authorize("admin")
    def add_protection():
        value = body(("network", "reason"), ("network", "reason"))
        return jsonify(investigation.protect(actor=g.operator["username"], **value)), 201

    @app.post("/api/v2/protections/<identity>/remove")
    @authorize("admin")
    def remove_protection(identity):
        value = body(("reason",), ("reason",))
        return jsonify(investigation.unprotect(identity, value["reason"], g.operator["username"]))

    @app.post("/api/v2/actions")
    @authorize()
    def manual_response():
        value = body(("alert_id", "ttl", "reason", "dry_run"), ("alert_id", "ttl", "reason", "dry_run"))
        return jsonify(response_engine.request(actor=g.operator["username"], **value)), 201

    @app.post("/api/v2/actions/<identity>/remove")
    @authorize()
    def remove_response(identity):
        body((), ())
        return jsonify(response_engine.remove(identity, g.operator["username"]))

    @app.post("/api/v2/actions/reconcile")
    @authorize()
    def reconcile():
        body((), ())
        response_engine.reconcile()
        return jsonify(status="Reconciled against available helper evidence")

    @app.post("/api/v2/lab-runs")
    @authorize()
    def start_scenario():
        value = body(("scenario",), ("scenario",))
        if not isinstance(value["scenario"], str) or value["scenario"] not in SCENARIOS:
            raise ValueError("Unknown controlled scenario")
        # Reserve before returning: two requests cannot create concurrent runs.
        with replay_start_lock:
            if replay.current or replay.lock.locked():
                return jsonify(error="A replay is already active"), 409
            identity = secrets.token_hex(16)
            replay.current = identity
            actor = g.operator["username"]
            worker = threading.Thread(
                target=replay.run, args=(value["scenario"], actor, identity), daemon=True
            )
            worker.start()
        return jsonify(id=identity, status="STARTING", origin="replay"), 202

    replay_start_lock = threading.Lock()

    @app.post("/api/v2/lab-runs/<identity>/cancel")
    @authorize()
    def cancel_scenario(identity):
        body((), ())
        if replay.current != identity:
            raise ValueError("Run is not active")
        replay.cancel.set()
        store.audit(g.operator["username"], "replay.cancel_requested", identity, "requested")
        return jsonify(status="Cancellation requested")

    @app.get("/api/v2/incidents/<identity>/report.<format>")
    def report(identity, format):
        if format not in ("json", "pdf"):
            raise ValueError("Report format must be json or pdf")
        snapshot = reports.snapshot(identity)
        data = reports.pdf(snapshot) if format == "pdf" else reports.json(snapshot)
        store.audit(g.operator["username"], "incident.exported", identity, "success", format=format)
        result = make_response(data)
        result.headers["Content-Type"] = "application/pdf" if format == "pdf" else "application/json"
        result.headers["Content-Disposition"] = f'attachment; filename="netshield-incident.{format}"'
        return result

    @app.get("/api/v2/incidents/<identity>/export")
    def export_incident(identity):
        if set(request.args) - {"format"}:
            raise ValueError("Export accepts only format=pdf or json")
        return report(identity, request.args.get("format", "json"))

    @app.post("/api/v2/settings")
    @authorize("admin")
    def update_settings():
        value = body((), ("event_retention_days", "evidence_retention_days"))
        for key, number in value.items():
            if type(number) is not int or not (1 if key == "event_retention_days" else 7) <= number <= (
                365 if key == "event_retention_days" else 3650
            ):
                raise ValueError("Retention outside bounds")
        existing = store.get("settings", "effective") or {}
        store.put("settings", {**existing, "id": "effective", **value, "actor": g.operator["username"]})
        store.audit(g.operator["username"], "settings.updated", "effective", "success", values=value)
        return jsonify(status="saved", **value)

    @app.post("/api/v2/rule-config")
    @authorize("admin")
    def configure_rules():
        from .rules import configured

        value = body(("overrides",), ("overrides",))
        configured(value["overrides"])
        store.put("settings", {"id": "rule-overrides", **value, "actor": g.operator["username"]})
        Pipeline(store, settings)
        store.audit(
            g.operator["username"],
            "rules.configured",
            "rule-overrides",
            "success",
            overrides=value["overrides"],
        )
        return jsonify(
            status="Saved; restart capture/service consumers to adopt. New replay runs use this configuration."
        )

    if settings.response_enabled:
        response_engine.reconcile()  # Startup success depends on kernel evidence, never on stored status.

    return app
