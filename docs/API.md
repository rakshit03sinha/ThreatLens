# ThreatLens REST API Inventory (v1)

ThreatLens exposes 31 versioned REST API endpoints under `/api/v1`. Interactive Swagger documentation is available at `/docs` and ReDoc at `/redoc`.

| # | HTTP Method | Endpoint Path | Description | Access / Roles |
|---|-------------|---------------|-------------|----------------|
| 1 | `GET` | `/api/v1/health` | Liveness health check | Public |
| 2 | `GET` | `/api/v1/ready` | Readiness and dependency check (DB + AI) | Public |
| 3 | `POST` | `/api/v1/auth/login` | Authenticate with username/password & obtain JWT | Public |
| 4 | `GET` | `/api/v1/auth/me` | Retrieve profile of currently authenticated user | Authenticated |
| 5 | `GET` | `/api/v1/metrics/dashboard` | Real-time SOC dashboard telemetry and counters | Public / Analyst |
| 6 | `GET` | `/api/v1/events` | Search and filter normalized telemetry events (paginated) | Public / Analyst |
| 7 | `GET` | `/api/v1/events/{event_id}` | Retrieve single event by UUID | Public / Analyst |
| 8 | `POST` | `/api/v1/ingest/event` | Ingest and normalize a single log event | Public / System |
| 9 | `POST` | `/api/v1/ingest/batch` | Ingest a batch of log records with job tracking | Public / System |
| 10 | `GET` | `/api/v1/ingest/jobs/{job_id}` | Check status and record counts of an ingestion job | Public / Analyst |
| 11 | `GET` | `/api/v1/ingest/formats` | List all 12 supported log formats and specifications | Public |
| 12 | `GET` | `/api/v1/rules` | List all 11 detection rules and active statuses | Public / Analyst |
| 13 | `GET` | `/api/v1/rules/{rule_id}` | Retrieve rule metadata, logic, and ATT&CK mapping | Public / Analyst |
| 14 | `PATCH` | `/api/v1/rules/{rule_id}/status` | Enable or disable a detection rule | Analyst / Admin |
| 15 | `GET` | `/api/v1/alerts` | Search and filter security alerts (paginated) | Public / Analyst |
| 16 | `GET` | `/api/v1/alerts/{alert_id}` | Get alert details, context data, and evidence links | Public / Analyst |
| 17 | `PATCH` | `/api/v1/alerts/{alert_id}` | Update alert disposition, status, or assignee | Analyst / Admin |
| 18 | `GET` | `/api/v1/iocs` | List indicators of compromise (paginated) | Public / Analyst |
| 19 | `POST` | `/api/v1/iocs` | Create or import threat intelligence indicator | Analyst / Admin |
| 20 | `GET` | `/api/v1/iocs/search` | Search for IOC by substring or exact value | Public / Analyst |
| 21 | `GET` | `/api/v1/iocs/{ioc_id}/matches` | Retrieve historical telemetry matches for an IOC | Public / Analyst |
| 22 | `GET` | `/api/v1/campaigns` | List correlated multi-stage incident campaigns | Public / Analyst |
| 23 | `GET` | `/api/v1/campaigns/{campaign_id}` | Retrieve campaign details and linked alert evidence | Public / Analyst |
| 24 | `PATCH` | `/api/v1/campaigns/{campaign_id}` | Update campaign lifecycle status or analyst notes | Analyst / Admin |
| 25 | `GET` | `/api/v1/scoring/{entity_type}/{entity_id}` | Retrieve explainable threat score factor breakdown | Public / Analyst |
| 26 | `POST` | `/api/v1/scoring/calculate` | Compute dynamic threat score snapshot | Public / Analyst |
| 27 | `POST` | `/api/v1/investigations/ask` | Ask an AI or deterministic SOC investigation question | Public / Analyst |
| 28 | `GET` | `/api/v1/investigations/history` | Retrieve historical incident investigation reports | Public / Analyst |
| 29 | `GET` | `/api/v1/playbooks` | Search and filter standard operating incident runbooks | Public / Analyst |
| 30 | `GET` | `/api/v1/playbooks/{playbook_id}` | Retrieve playbook containment & remediation steps | Public / Analyst |
| 31 | `GET` | `/api/v1/audit/logs` | Review administrative audit logs and changes | Analyst / Admin |

## Authentication and Role Authorization
- Uses standard JWT Bearer tokens signed with HS256.
- Roles:
  - `admin`: Full administrative control, rule toggles, system settings.
  - `analyst`: Triage alerts, update campaigns, create IOCs, perform AI investigations.
  - `readonly`: Query telemetry, review reports.

