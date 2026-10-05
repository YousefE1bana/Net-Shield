"""Versioned SQLite repositories; typed query columns plus versioned JSON DTOs.

All writes serialize through transaction(). WAL readers use separate connections.
Legacy tables are preserved, not relabelled as trustworthy V2 observations.
"""

from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import uuid
from werkzeug.security import generate_password_hash

ENTITIES = (
    "sensors",
    "events",
    "flows",
    "metrics",
    "rules",
    "alerts",
    "occurrences",
    "incidents",
    "incident_links",
    "assets",
    "bindings",
    "actions",
    "exceptions",
    "protections",
    "audit",
    "lab_runs",
    "settings",
)
FIELDS = (
    "origin",
    "run_id",
    "sensor_id",
    "event_time",
    "source_ip",
    "target_ip",
    "protocol",
    "rule_id",
    "severity",
    "status",
    "key",
    "incident_id",
    "alert_id",
    "flow_id",
    "asset_id",
)


def uid():
    return str(uuid.uuid4())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.local = threading.local()
        self.migrate()

    @contextmanager
    def connection(self):
        if getattr(self.local, "conn", None):
            yield self.local.conn
            return
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        if getattr(self.local, "conn", None):
            yield self.local.conn
            return
        with self.lock, self.connection() as conn:
            self.local.conn = conn
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                self.local.conn = None

    def backup(self, destination):
        destination = Path(destination).resolve()
        if destination == self.path or destination.exists():
            raise ValueError("Backup destination must be a new file")
        with self.lock, self.connection() as source, sqlite3.connect(destination) as target:
            source.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Backup integrity failed")
        destination.chmod(0o600)
        return destination

    def migrate(self):
        with self.connection() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        if version > 2 or (
            version == 0 and tables and not {"alerts", "blocked_ips", "traffic_logs"} <= tables
        ):
            raise ValueError("Unrecognized or future database schema; no changes made")
        if version in (1, 2):
            required = {self.table(e) for e in ENTITIES if version == 2 or e != "protections"}
            if not required <= tables:
                raise ValueError("Unrecognized or incomplete versioned schema; no changes made")
            with self.connection() as conn:
                for table in required:
                    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                    if not {"id", "body", *FIELDS} <= columns:
                        raise ValueError("Incompatible versioned schema columns; no changes made")
        if version == 2:
            if (
                not {self.table(e) for e in ENTITIES} <= tables
                or not {"v2_operators", "v2_sessions", "v2_login_limits"} <= tables
            ):
                raise ValueError("Incomplete V2 schema; restore a verified backup")
            return
        if tables:
            self.backup(str(self.path) + f".before-v2-{time.time_ns()}.bak")
        with self.transaction() as conn:
            for entity in ENTITIES:
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS v2_{entity}(id TEXT PRIMARY KEY,origin TEXT,run_id TEXT,sensor_id TEXT,event_time REAL,source_ip TEXT,target_ip TEXT,protocol TEXT,rule_id TEXT,severity TEXT,status TEXT,key TEXT,incident_id TEXT,alert_id TEXT,flow_id TEXT,asset_id TEXT,body TEXT NOT NULL)"
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS v2_{entity}_time ON v2_{entity}(origin,run_id,event_time DESC)"
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS v2_{entity}_source ON v2_{entity}(source_ip,target_ip)"
                )
                conn.execute(f"CREATE INDEX IF NOT EXISTS v2_{entity}_status ON v2_{entity}(status,rule_id)")
                conn.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS v2_{entity}_key ON v2_{entity}(key) WHERE key IS NOT NULL"
                )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS v2_operators(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,created REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS v2_sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES v2_operators(username),csrf TEXT NOT NULL,expires REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS v2_login_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,started REAL NOT NULL)"
            )
            conn.execute("PRAGMA user_version=2")
        with self.connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
        self.path.chmod(0o600)

    @staticmethod
    def table(entity):
        if entity not in ENTITIES:
            raise ValueError("Unknown resource")
        return "v2_" + entity

    def put(self, entity, value):
        table = self.table(entity)
        value = dict(value)
        value.setdefault("id", uid())
        value.setdefault("event_time", time.time())
        value.setdefault("ingest_time", time.time())
        if not math.isfinite(float(value["event_time"])):
            raise ValueError("Invalid event time")
        body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(body.encode()) > 262144:
            raise ValueError("Record exceeds metadata budget")
        with self.transaction() as conn:
            conn.execute(
                f"INSERT INTO {table}(id,{','.join(FIELDS)},body) VALUES({','.join('?' for _ in range(len(FIELDS) + 2))}) ON CONFLICT(id) DO UPDATE SET "
                + ",".join(f"{f}=excluded.{f}" for f in (*FIELDS, "body")),
                [value["id"], *(value.get(f) for f in FIELDS), body],
            )
        return value

    def get(self, entity, identity):
        if not isinstance(identity, str) or len(identity) > 160:
            raise ValueError("Invalid record identifier")
        with self.connection() as conn:
            row = conn.execute(f"SELECT body FROM {self.table(entity)} WHERE id=?", (identity,)).fetchone()
        return json.loads(row[0]) if row else None

    def keyed(self, entity, key):
        with self.connection() as conn:
            row = conn.execute(f"SELECT body FROM {self.table(entity)} WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, entity, filters=None, limit=100, offset=0):
        table = self.table(entity)
        limit, offset = int(limit), int(offset)
        if not 1 <= limit <= 250 or not 0 <= offset <= 1000000:
            raise ValueError("Pagination outside bounds")
        where, params = self.selection(filters)
        with self.connection() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM {table}{where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT body FROM {table}{where} ORDER BY event_time DESC,id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return {
            "items": [json.loads(r[0]) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "schema_version": 2,
        }

    @staticmethod
    def selection(filters):
        conditions, params = [], []
        aliases = {
            "source": "source_ip",
            "destination": "target_ip",
            "sensor": "sensor_id",
            "rule": "rule_id",
            "run": "run_id",
        }
        for key, value in (filters or {}).items():
            if value in (None, ""):
                continue
            key = aliases.get(key, key)
            if key in FIELDS:
                conditions.append(f"{key}=?")
                params.append(value)
            elif key in ("start", "end"):
                if not math.isfinite(float(value)):
                    raise ValueError("Invalid time filter")
                conditions.append("event_time" + (">=?" if key == "start" else "<=?"))
                params.append(float(value))
            elif key in ("source_port", "target_port"):
                if not str(value).isdigit() or not 0 <= int(value) <= 65535:
                    raise ValueError("Invalid port filter")
                conditions.append(f"json_extract(body,'$.{key}')=?")
                params.append(int(value))
            elif key == "q":
                conditions.append("body LIKE ? ESCAPE '\\'")
                params.append(
                    "%" + str(value)[:128].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                )
            else:
                raise ValueError("Unknown filter: " + key)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        return where, params

    def overview(self, filters):
        where, params = self.selection(filters)
        with self.connection() as conn:
            alerts = [
                dict(r)
                for r in conn.execute(
                    f"SELECT severity,status,COUNT(*) count FROM v2_alerts{where} GROUP BY severity,status",
                    params,
                )
            ]
            protocols = [
                dict(r)
                for r in conn.execute(
                    f"SELECT protocol,SUM(json_extract(body,'$.packets')) packets,SUM(json_extract(body,'$.bytes')) bytes FROM v2_metrics{where} GROUP BY protocol",
                    params,
                )
            ]
            points = [
                dict(r)
                for r in conn.execute(
                    f"SELECT event_time,SUM(json_extract(body,'$.packets')) packets,SUM(json_extract(body,'$.bytes')) bytes,SUM(json_extract(body,'$.alert_occurrences')) alerts FROM v2_metrics{where} GROUP BY event_time ORDER BY event_time DESC LIMIT 600",
                    params,
                )
            ]
            top = [
                json.loads(r[0])
                for r in conn.execute(
                    f"SELECT body FROM v2_flows{where} ORDER BY json_extract(body,'$.bytes') DESC LIMIT 8",
                    params,
                )
            ]
        return {
            "schema_version": 2,
            "alert_counts": alerts,
            "protocols": protocols,
            "points": list(reversed(points)),
            "top_flows": top,
            "chart_limit": 600,
            "chart_semantics": "One-second observed buckets; gaps are missing observations, not measured zeros.",
        }

    def audit(self, actor, operation, target, result, **metadata):
        return self.put(
            "audit",
            {
                "actor": actor,
                "operation": operation,
                "target": target,
                "result": result,
                "metadata": metadata,
            },
        )

    def prune(self, event_days=7, evidence_days=90, now=None):
        now = time.time() if now is None else now
        if (
            type(event_days) is not int
            or type(evidence_days) is not int
            or not 1 <= event_days <= 365
            or not 7 <= evidence_days <= 3650
        ):
            raise ValueError("Retention outside bounds")
        counts = {}
        with self.transaction() as conn:
            for entity in ENTITIES:
                if entity in ("rules", "settings", "protections", "sensors"):
                    continue
                # Historical replay timestamp is preserved. Retention is based on
                # ingestion for raw events; run/alert event-time retention is explicit.
                days = event_days if entity in ("events", "flows", "metrics") else evidence_days
                clock = "COALESCE(json_extract(body,'$.ingest_time'),event_time)"
                if entity == "actions":
                    clause = " AND status IN ('REMOVED','FAILED')"
                else:
                    clause = ""
                counts[entity] = conn.execute(
                    f"DELETE FROM {self.table(entity)} WHERE {clock}<?{clause}", (now - days * 86400,)
                ).rowcount
        self.audit("local-retention", "retention.pruned", "database", "success", counts=counts)
        return counts

    def create_operator(self, username, password, role="admin"):
        if not isinstance(username, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", username):
            raise ValueError("Username must contain 3–32 simple characters")
        if (
            not isinstance(password, str)
            or not 12 <= len(password) <= 256
            or role not in ("admin", "operator", "viewer")
        ):
            raise ValueError("Password must contain 12–256 characters; role must be valid")
        password_hash = generate_password_hash(password, method="scrypt")
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO v2_operators VALUES(?,?,?,?)", (username, password_hash, role, time.time())
            )
            self.audit("local-cli", "operator.created", username, "success", role=role)

    def operators(self):
        with self.connection() as conn:
            return [dict(r) for r in conn.execute("SELECT username,role,created FROM v2_operators")]

    def operator_hash(self, username):
        with self.connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM v2_operators WHERE username=?", (username,)
            ).fetchone()
        return row[0] if row else None

    def session(self, token):
        with self.connection() as conn:
            row = conn.execute(
                "SELECT s.username,s.csrf,o.role FROM v2_sessions s JOIN v2_operators o USING(username) WHERE token_hash=? AND expires>?",
                (digest(token), time.time()),
            ).fetchone()
        return dict(row) if row else None

    def start_session(self, username):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.transaction() as conn:
            conn.execute("DELETE FROM v2_sessions WHERE expires<=?", (time.time(),))
            conn.execute(
                "INSERT INTO v2_sessions VALUES(?,?,?,?)",
                (digest(token), username, csrf, time.time() + 28800),
            )
        return token, csrf

    def end_session(self, token):
        with self.transaction() as conn:
            conn.execute("DELETE FROM v2_sessions WHERE token_hash=?", (digest(token),))

    def login_allowed(self, address):
        key, now = digest(address), time.time()
        with self.transaction() as conn:
            conn.execute("DELETE FROM v2_login_limits WHERE started<?", (now - 300,))
            row = conn.execute("SELECT count FROM v2_login_limits WHERE key=?", (key,)).fetchone()
            if row and row[0] >= 10:
                return False
            conn.execute(
                "INSERT INTO v2_login_limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1",
                (key, now),
            )
        return True
