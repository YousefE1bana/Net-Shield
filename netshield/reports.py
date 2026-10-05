"""Local, bounded SOC exports. No remote rendering, paths or embedded secrets."""

from datetime import datetime, timezone
from io import BytesIO
import json
import time
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle


def stamp(value):
    return (
        datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if value is not None
        else "Not observed"
    )


class Reports:
    def __init__(self, store):
        self.store = store

    def snapshot(self, identity, generated_at=None):
        with self.store.transaction():
            incident = self.store.get("incidents", identity)
            if not incident:
                raise ValueError("Incident not found")
            alerts = [self.store.get("alerts", a) for a in incident.get("alert_ids", [])]
            missing_alerts = sum(a is None for a in alerts)
            alerts = [a for a in alerts if a]
            flow_ids = sorted({f for a in alerts for f in a.get("flow_ids", [])})
            flows = [self.store.get("flows", f) for f in flow_ids[:100]]
            occurrences, truncated = [], []
            if missing_alerts or any(f is None for f in flows):
                truncated.append("Linked evidence is no longer available, possibly due to retention.")
            for alert in alerts:
                result = self.store.list("occurrences", {"alert_id": alert["id"]}, limit=100)
                occurrences.extend(result["items"])
                if result["total"] > 100:
                    truncated.append("Occurrence history capped at 100 per alert: " + alert["id"])
            actions = self.store.list("actions", {"incident_id": identity}, limit=100)
            if len(occurrences) > 100:
                truncated.append(
                    "PDF timeline shows the latest 100 occurrences; JSON retains the bounded per-alert snapshot."
                )
            if len(flow_ids) > 100 or actions["total"] > 100:
                truncated.append("Flow/response export budget reached (100 records each)")
            return {
                "schema_version": 2,
                "product": "NetShield",
                "report_type": "Incident evidence report",
                "generated_at": generated_at if generated_at is not None else time.time(),
                "incident": incident,
                "alerts": sorted(alerts, key=lambda a: a["id"]),
                "flows": [f for f in flows if f],
                "occurrences": sorted(occurrences, key=lambda o: (o["event_time"], o["id"])),
                "actions": actions["items"],
                "truncation": truncated,
                "generation": {
                    "renderer": "Local ReportLab",
                    "template_version": "2.0.0",
                    "integrity": "No signed forensic chain of custody",
                },
                "observed_indicators": {
                    "source": incident.get("source_ip"),
                    "destination": incident.get("target_ip"),
                    "interpretation": "Observed network endpoints, not confirmed malicious IOCs",
                },
                "affected_observed_addresses": sorted(
                    {x for a in alerts for x in (a.get("source_ip"), a.get("target_ip")) if x}
                ),
                "final_disposition": incident.get("status", "UNKNOWN"),
                "false_positive_assessment": "Not classified by this template; consult attributable analyst notes.",
                "recommendations": [
                    "Confirm authorized scanning/automation and observation-point coverage.",
                    "Review exact rule threshold, related conversations and trusted service outcomes.",
                    "Use scoped expiring exceptions for explained benign activity; protect response infrastructure separately.",
                    "Verify kernel state and connectivity before concluding any live mitigation succeeded.",
                ],
                "limitations": [
                    "Network metadata indicators do not establish compromise or operator identity.",
                    "No payloads, credentials or decrypted HTTPS content are included.",
                    "Replay and isolated-lab evidence cannot authorize live firewall changes.",
                    "Historical records may have expired under retention policy; export is bounded.",
                ],
                "assessment": "Analyst resolution recorded; review supporting notes."
                if incident.get("status") == "RESOLVED"
                else "Open investigation; no final analyst conclusion recorded.",
            }

    @staticmethod
    def json(snapshot):
        return json.dumps(snapshot, sort_keys=True, indent=2, allow_nan=False).encode()

    def pdf(self, snapshot):
        output = BytesIO()
        doc = SimpleDocTemplate(
            output,
            pagesize=(210 * mm, 297 * mm),
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=23 * mm,
            bottomMargin=20 * mm,
            title="NetShield incident evidence",
            author="NetShield local operator",
        )
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                "NSBody",
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#25333e"),
                spaceAfter=5,
            )
        )
        styles.add(
            ParagraphStyle(
                "NSHeading",
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=16,
                textColor=colors.HexColor("#126c64"),
                spaceBefore=14,
                spaceAfter=8,
                keepWithNext=True,
            )
        )
        styles.add(
            ParagraphStyle(
                "NSMono", fontName="Courier", fontSize=7, leading=10, wordWrap="CJK", alignment=TA_LEFT
            )
        )

        def paragraph(value, style="NSBody"):
            return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])

        def table(rows, widths):
            result = Table(
                [[paragraph(cell) for cell in row] for row in rows],
                colWidths=widths,
                repeatRows=1,
                hAlign="LEFT",
            )
            result.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3efed")),
                        ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#7f9c98")),
                        ("LINEBELOW", (0, 1), (-1, -1), 0.3, colors.HexColor("#d5dedf")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            return result

        incident = snapshot["incident"]
        origin = incident.get("origin", "unknown").upper()
        story = [
            paragraph("INCIDENT EVIDENCE REPORT", "NSHeading"),
            paragraph("NetShield", "Title"),
            paragraph(
                origin
                + " / "
                + incident.get("status", "UNKNOWN")
                + " / "
                + incident.get("severity", "Unscored")
            ),
            paragraph("Incident " + incident["id"], "NSMono"),
            paragraph("Generated " + stamp(snapshot["generated_at"])),
            paragraph("Executive assessment", "NSHeading"),
            paragraph(snapshot["assessment"]),
            paragraph(incident.get("grouping_reason", "No automatic correlation rationale recorded.")),
            table(
                [
                    ["Observed scope", "Value"],
                    [
                        "Source → destination",
                        incident.get("source_ip", "Unknown") + " → " + incident.get("target_ip", "Unknown"),
                    ],
                    [
                        "Sensor / interface",
                        incident.get("sensor_id", "Unknown") + " / " + incident.get("interface", "Unknown"),
                    ],
                    ["Run", incident.get("run_id") or "Live observations"],
                    [
                        "First / last observed",
                        stamp(incident.get("first_seen")) + " / " + stamp(incident.get("last_seen")),
                    ],
                ],
                [48 * mm, 126 * mm],
            ),
            paragraph("Observed evidence", "NSHeading"),
        ]
        if not snapshot["alerts"]:
            story.append(paragraph("No linked alert evidence remains in this snapshot."))
        for alert in snapshot["alerts"]:
            evidence = alert.get("evidence", {})
            story.extend(
                [
                    paragraph(alert.get("name", alert.get("rule_id", "Unknown rule")), "NSHeading"),
                    paragraph(
                        f"{alert.get('rule_id')} v{alert.get('rule_version', 'unknown')} / severity {alert.get('severity', 'unknown')} / confidence {alert.get('confidence', 'unknown')} / status {alert.get('status', 'unknown')}"
                    ),
                    paragraph(alert.get("description", "No detection description recorded.")),
                    paragraph(json.dumps(evidence, sort_keys=True), "NSMono"),
                    paragraph("Occurrences: " + str(alert.get("occurrences", 0))),
                ]
            )
            if alert.get("attack"):
                story.append(
                    paragraph(
                        "ATT&CK "
                        + alert["attack"]
                        + ": "
                        + alert.get("mapping_rationale", "No rationale recorded")
                    )
                )
        story.extend(
            [
                paragraph("Event timeline (UTC)", "NSHeading"),
                table(
                    [["Time", "Rule", "Observed / threshold"]]
                    + [
                        [
                            stamp(o["event_time"]),
                            o.get("rule_id", "Unknown"),
                            str(o.get("evidence", {}).get("observed", "Unknown"))
                            + " / "
                            + str(o.get("evidence", {}).get("threshold", "Unknown")),
                        ]
                        for o in snapshot["occurrences"][-100:]
                    ],
                    [64 * mm, 66 * mm, 44 * mm],
                ),
                paragraph("Related conversations", "NSHeading"),
            ]
        )
        if snapshot["flows"]:
            story.append(
                table(
                    [["Endpoints / protocol", "Packets / bytes", "Duration"]]
                    + [
                        [
                            f"{f['source_ip']}:{f['source_port']} → {f['target_ip']}:{f['target_port']} / {f['protocol']}",
                            f"{f['packets']} / {f['bytes']}",
                            str(round(f["duration"], 3)) + "s",
                        ]
                        for f in snapshot["flows"]
                    ],
                    [108 * mm, 38 * mm, 28 * mm],
                )
            )
        else:
            story.append(
                paragraph(
                    "No related packet conversation was observed (service-event evidence may have no flow)."
                )
            )
        story.append(paragraph("Response and verification", "NSHeading"))
        verified = [
            a
            for a in snapshot["actions"]
            if not a.get("dry_run") and a.get("verification") in ("kernel_present", "kernel_absent")
        ]
        if not verified:
            story.append(paragraph("No verified live enforcement is present in this evidence snapshot."))
        for action in snapshot["actions"]:
            story.append(
                paragraph(
                    f"{action['target_ip']} / {action['status']} / {action['verification']} / requested by {action['requested_by']} / expiry {stamp(action['expires_at'])} / authority {'dry run' if action.get('dry_run') else action.get('origin', 'unknown')} / scope {action.get('helper_scope', 'Not verified')}"
                )
            )
        story.append(paragraph("Analyst notes", "NSHeading"))
        for note in incident.get("notes", []):
            story.append(paragraph(stamp(note["time"]) + " / " + note["actor"] + ": " + note["text"]))
        if not incident.get("notes"):
            story.append(paragraph("No analyst notes recorded."))
        story.extend(
            [
                paragraph("Assessment and recommendations", "NSHeading"),
                paragraph(snapshot["false_positive_assessment"]),
                paragraph("Observed addresses: " + ", ".join(snapshot["affected_observed_addresses"])),
            ]
        )
        story.extend(paragraph(item) for item in snapshot["recommendations"])
        story.append(paragraph("Coverage and limitations", "NSHeading"))
        story.append(
            paragraph("Renderer: local ReportLab / template 2.0.0. No signed forensic chain of custody.")
        )
        story.extend(paragraph(item) for item in [*snapshot["limitations"], *snapshot["truncation"]])

        def furniture(canvas, document):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor("#126c64"))
            canvas.rect(18 * mm, 280 * mm, 174 * mm, 1.2 * mm, fill=1, stroke=0)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#53646d"))
            canvas.drawString(18 * mm, 13 * mm, "NetShield · Local evidence export · " + origin)
            canvas.drawRightString(192 * mm, 13 * mm, str(document.page))
            canvas.restoreState()

        doc.build(story, onFirstPage=furniture, onLaterPages=furniture)
        return output.getvalue()
