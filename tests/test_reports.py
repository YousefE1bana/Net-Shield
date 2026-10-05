import io
import json
from pypdf import PdfReader
from netshield.replay import Replay
from netshield.reports import Reports
from netshield.settings import Settings
from netshield.store import Store


def test_report_joins_evidence_and_pdf_has_truthful_scope(tmp_path):
    store = Store(tmp_path / "test.db")
    Replay(store, Settings(data_dir=tmp_path)).run("port-scan", "analyst")
    incident = store.list("incidents")["items"][0]
    reports = Reports(store)
    first = reports.snapshot(incident["id"], generated_at=123)
    assert reports.json(first) == reports.json(reports.snapshot(incident["id"], generated_at=123))
    parsed = json.loads(reports.json(first))
    assert parsed["alerts"] and parsed["flows"] and parsed["occurrences"]
    content = reports.pdf(first)
    pages = PdfReader(io.BytesIO(content)).pages
    words = "".join(page.extract_text() for page in pages)
    assert "REPLAY" in words and "No verified live enforcement" in words
    assert "Observed evidence" in words and "NetShield" in words
    assert "Same observed source/target" in words


def test_notes_are_printed_as_text_not_report_markup(tmp_path):
    store = Store(tmp_path / "test.db")
    incident = store.put(
        "incidents",
        {
            "origin": "replay",
            "status": "OPEN",
            "notes": [{"text": "<script>alert(1)</script>", "actor": "analyst", "time": 1}],
        },
    )
    reports = Reports(store)
    pdf = reports.pdf(reports.snapshot(incident["id"]))
    words = "".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
    assert "<script>alert(1)</script>" in words
