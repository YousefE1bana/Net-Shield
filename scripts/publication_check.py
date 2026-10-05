"""Review curated source hygiene; this does not certify deployment or publish files."""

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
ROOT_FILES = [
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "requirements-dev.txt",
    "config.example.json",
    ".gitignore",
    ".gitattributes",
    "install.sh",
]
PUBLIC_DIRS = ["netshield", "scripts", "deploy", ".github", "docs", "tests"]
EXCLUDED_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "publication-manifest.json",
    "serve_console.py",
    "console-browser.cjs",
    "console-data.test.mjs",
    "browser-verified-incident.pdf",
}
SECRET_PATTERNS = [
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    rb"gh[pousr]_[A-Za-z0-9]{30,}",
    rb"AKIA[0-9A-Z]{16}",
]


def candidates():
    files = [ROOT / p for p in ROOT_FILES if (ROOT / p).is_file()]
    for directory in PUBLIC_DIRS:
        files.extend(
            p
            for p in (ROOT / directory).rglob("*")
            if p.is_file() and not set(p.parts) & EXCLUDED_NAMES and not p.name.endswith("-qa.json")
        )
    files.extend(
        ROOT / p
        for p in [
            "dashboard/__init__.py",
            "dashboard/app.py",
            "dashboard/templates/index.html",
            "dashboard/templates/login.html",
            "dashboard/static/icons.svg",
            "dashboard/static/css/dashboard.css",
            "dashboard/static/css/login.css",
            "dashboard/static/js/dashboard.js",
            "dashboard/static/js/v2-console.mjs",
            "dashboard/static/js/ui.mjs",
            "dashboard/static/js/login.mjs",
        ]
    )
    files.extend((ROOT / "dashboard/static/brand").glob("*.svg"))
    return sorted(set(files))


def inspect():
    private = ROOT / ".workbench/qa-credentials.json"
    password = json.loads(private.read_text())["password"].encode() if private.exists() else b""
    entries, findings = [], []
    for file in candidates():
        relative = file.relative_to(ROOT).as_posix()
        data = file.read_bytes()
        if (
            file.is_symlink()
            or file.suffix.lower()
            in {".db", ".bak", ".log", ".pyc", ".env", ".key", ".pem", ".crt", ".p12", ".pfx", ".tmp"}
            or "-wal" in file.name
            or "-shm" in file.name
        ):
            findings.append(relative + ": generated/private file")
        if file.suffix.lower() in {".pcap", ".pcapng"} and relative != "tests/fixtures/port-scan.pcap":
            findings.append(relative + ": non-allowlisted capture")
        if password and password in data:
            findings.append(relative + ": private QA credential")
        if any(re.search(pattern, data) for pattern in SECRET_PATTERNS):
            findings.append(relative + ": secret-shaped content")
        entries.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {
        "hygiene": "PASS" if not findings else "FAIL",
        "files": entries,
        "findings": findings,
        "license": "Apache-2.0" if (ROOT / "LICENSE").is_file() else "MISSING",
        "runtime_limit": "New installer Linux lifecycle acceptance remains pending; see docs/LINUX-ACCEPTANCE.md.",
        "scope": "Curated source hygiene only, not Git tracking proof, legal review or runtime certification.",
        "excluded": "Original V1 engine/attack controls, setup.sh, dashboard/api.py/models.py and unused legacy browser modules remain local; .workbench, venv, DB/log/cache/build/dist are excluded.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".workbench/publication-manifest.json")
    args = parser.parse_args()
    result = inspect()
    target = ROOT / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "hygiene": result["hygiene"],
                "files": len(result["files"]),
                "findings": result["findings"],
                "license": result["license"],
            },
            indent=2,
        )
    )
    raise SystemExit(0 if not result["findings"] and result["license"] != "MISSING" else 1)
