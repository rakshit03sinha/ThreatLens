# ThreatLens Explainable Threat Scoring Engine

ThreatLens implements a deterministic, explainable risk scoring model that calculates a normalized risk score between 0.0 and 100.0 for every alert and correlated campaign.

## Mathematical Formulation

The threat score \(S\) is computed as a weighted sum of five bounded factors:

$$S = \min\left(100.0, \max\left(0.0, w_{\text{sev}} F_{\text{sev}} + w_{\text{conf}} F_{\text{conf}} + w_{\text{freq}} F_{\text{freq}} + w_{\text{ioc}} F_{\text{ioc}} + w_{\text{camp}} F_{\text{camp}}\right)\right)$$

### Default Factor Weights:
- **Severity Factor ($w_{\text{sev}} = 0.35$ / 35%)**:
  - `CRITICAL` = 100.0
  - `HIGH` = 75.0
  - `MEDIUM` = 50.0
  - `LOW` = 25.0
  - `INFORMATIONAL` = 12.5
- **Analytic Confidence ($w_{\text{conf}} = 0.20$ / 20%)**: Confidence rating of the detection rule (0 to 100%).
- **Telemetry Frequency ($w_{\text{freq}} = 0.15$ / 15%)**:
  - 1 event: 20.0 pts
  - 2–5 events: 50.0 pts
  - 6–20 events: 80.0 pts
  - >20 events: 100.0 pts
- **IOC Intelligence ($w_{\text{ioc}} = 0.20$ / 20%)**: Bounded match confidence (50.0 to 100.0) if a confirmed malicious IP, domain, or hash matches threat intelligence; 0.0 otherwise.
- **Campaign Correlation ($w_{\text{camp}} = 0.10$ / 10%)**: Scaled breadth score ($40.0 + 15.0 \times \text{LinkedAlerts}$) if part of an active multi-stage incident campaign; 0.0 otherwise.

## Factor Breakdown & Explainability
Every calculated score is persisted alongside a human-readable explanation and machine-readable JSON factor breakdown:

```json
{
  "severity_factor": 35.0,
  "confidence_factor": 16.0,
  "frequency_factor": 7.5,
  "ioc_factor": 19.0,
  "campaign_factor": 10.0,
  "raw_score": 87.5,
  "normalized_score": 87.5
}
```
*Sample Explanation*: "Base rule severity 'CRITICAL' contributed 35.0 pts; Analytic confidence (80.0%) added 16.0 pts; Event frequency (5 telemetry occurrences) added 7.5 pts; Confirmed Threat Intel IOC indicator match added 19.0 pts; Multi-alert campaign correlation (3 linked alerts) added 10.0 pts. Final explainable threat score: 87.5/100."

