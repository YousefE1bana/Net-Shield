"""Private local QA bootstrap; credentials never enter tracked fixtures or output."""

import json
from pathlib import Path
import secrets
from netshield.store import Store

if __name__ == "__main__":
    directory = Path(".workbench/qa").resolve()
    config = {"data_dir": str(directory), "port": 18483}
    store = Store(directory / "netshield.db")
    username, password = "qa_" + secrets.token_hex(4), secrets.token_urlsafe(24)
    store.create_operator(username, password)
    private = Path(".workbench/qa-credentials.json")
    private.write_text(json.dumps({"username": username, "password": password}))
    private.chmod(0o600)
    Path(".workbench/qa-config.json").write_text(json.dumps(config))
    print("Private loopback QA operator prepared for port 18483.")
