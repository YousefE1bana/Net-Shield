# Incident SOC reports

Open an incident drawer and choose Download PDF or Download JSON. The authenticated read endpoint snapshots linked alerts, bounded occurrences/flows, analyst notes and response actions in a transaction. Rendering is local ReportLab; no internet renderer, shell, remote image or embedded credentials is used. A CLI export also exists: `python -m netshield report INCIDENT_ID reports/new-report.pdf --format pdf`.

Reports include incident ID/time/status/severity, executive assessment, first/last observed endpoints and sensor/run, exact rule IDs/versions/evidence, occurrence timeline, related conversations, qualified ATT&CK rationale, analyst notes, response actor/state/expiry/verification, final status, observed indicators, false-positive assessment limits, recommendations, coverage/provenance and template metadata. Analyst resolution is not automatically classified as false positive or compromise. Consult attributed notes for disposition.

JSON is deterministic for a fixed snapshot and generation timestamp; PDF contents use deterministic templates but PDF bytes include rendering metadata. Snapshot budgets: 100 flows/actions, 100 occurrences per alert, 128 linked alerts; PDF timeline shows latest100 occurrences with a truncation notice. Retention may remove older raw evidence; missing references are omitted with coverage warnings. No signed forensic integrity/chain of custody is claimed.

Text is escaped before ReportLab paragraph markup. Payloads/passwords/opaque session tokens are excluded. Export itself is audited. IPs/MACs can still be sensitive: share only permissioned sanitized evidence.

The actual sample [flagship replay report](assets/v2-final/flagship-replay.pdf) describes a resolved offline validation with a retired manual dry run, not an enforced block. A second actual [IDM-downloaded report](assets/v2-final/sample-replay-incident.pdf) was copied from the operator's Downloads/Documents and both pages rendered/inspected. Download managers may intercept browser download events; authenticated PDF status/content and resulting file must be checked independently.
