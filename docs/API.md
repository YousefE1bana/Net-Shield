# Authenticated API V2

All `/api/*` resources require a server session. Legacy routes are not registered, and `/socket.io/*` returns410. Login GET renders the form; GET `/auth/session` creates an expiring login CSRF nonce; POST `/auth/login` accepts username/password/csrf and rotates the session; POST `/auth/logout` revokes it. Mutations require matching `X-CSRF-Token`, same-origin policy and role. Viewer reads; operator investigates/runs offline scenarios/manual response; admin also configures rules/retention/protections.

GET collections: events, flows, metrics, alerts, occurrences, incidents, incident-links, assets, bindings, rules, actions, exceptions, protections, audit, lab-runs, sensors. GET collection/ID gives an object. Collections return items,total,limit,offset,schema_version=2; limit1–250, offset0–1000000. Filters: start/end finite event time, origin, run, sensor, source/destination literal address strings, protocol, rule, severity,status, incident_id,alert_id,flow_id,asset_id, source_port,target_port, q literal substring <=128 chars. Unknown filters are rejected. Filtering a field absent from a resource yields no matches; it does not invent joins.

Special GET: status (health), overview (real aggregate buckets/counts/top flows), scenarios (fixed catalogue), settings (safe values), rule-config (saved typed overrides). `rules?status=CURRENT` selects configured inventory; archived rule versions remain for evidence. `/incidents/ID/export?format=pdf|json` or `/report.pdf|json` returns an authenticated attachment.

| Mutation | Body |
|---|---|
| PATCH alerts/ID or incidents/ID | status OPEN/ACKNOWLEDGED/RESOLVED and/or note <=2000 |
| PATCH assets/ID | label <=80 |
| POST incidents/ID/detach | alert_id, reason |
| POST exceptions | rule_id,origin,duration,reason; source_ip and/or target_ip; optional sensor_id |
| POST exceptions/ID/revoke | empty object |
| POST protections (admin) | network CIDR,reason |
| POST protections/ID/remove (admin) | reason; helper policy remains independent |
| POST actions | alert_id,ttl,reason,dry_run:boolean |
| POST actions/ID/remove or actions/reconcile | empty object |
| POST lab-runs | scenario: fixed catalogue ID only |
| POST lab-runs/ID/cancel | empty object; current local runner only |
| POST settings (admin) | event_retention_days,evidence_retention_days |
| POST rule-config (admin) | overrides: known-rule map of threshold/window/enabled |

400 invalid input,401 no session,403 role/CSRF/origin denial,404 missing resource,409 busy runner,410 retired socket,413 oversized body,429 login budget,503 storage dependency unavailable. Body budget16KiB; metadata records <=256KiB. Errors do not expose SQL/credential values.

No generic event-upload API exists. Trusted local service contract accepts kind ssh_auth/web_auth/http_request/operational, event_time, literal source_ip/target_ip, target_port, outcome failure/success, bounded component/state/error_code; caller origin/run/sensor fields are rejected. SSH journal ingress validates root/unit metadata. The web batch adapter accepts web_auth/http_request only from a root-owned non-group/world-writable regular file. Replaying the same spool duplicates evidence; producer spool rotation/idempotent event IDs are not implemented.

`GET /incidents/ID/evidence` returns a bounded report snapshot for the drawer (latest100 occurrences, up to100flows/actions). Rule collection DTOs include real alert counts and last trigger for the exact version across **all retained origins**; this catalogue statistic is explicitly broader than the current traffic scope.
