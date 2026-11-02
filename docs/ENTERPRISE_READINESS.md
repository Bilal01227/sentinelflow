# Enterprise readiness and deployment boundary

## Current positioning

SentinelFlow is an offline, sensor-agnostic network-flow analytics engine with
Zeek and Suricata JSONL file adapters. It is intended for engineering evaluation,
controlled pilots, and research after local validation. It is not a turnkey
enterprise NIDS, SIEM, NDR appliance, inline IPS, or certified security control.

## Security architecture principles

1. Least privilege: run ingestion/scoring as an unprivileged service account.
   Grant read-only access to sensor exports and write access only to outputs.
2. Zero implicit trust: treat sensor files and event fields as untrusted.
   Validate before feature extraction and model inference.
3. Data minimization: flow metadata can identify users and devices. Define
   lawful purpose, access, retention, encryption, and deletion controls.
4. No autonomous blocking: detections are review signals. Response remains
   with an authorized operator and established change control.
5. Reproducibility: record sensor version, export configuration, baseline
   period, model parameters, rule configuration, and evaluation window.
6. Separation of duties: separate baseline preparation, alert review, and
   production network changes.

## Required before production deployment

- Live ingestion with bounded queues, backpressure, replay, idempotency,
  checkpointing, dead-letter handling, and tested recovery.
- Multi-tenant identity, SSO/OIDC, role-based authorization, immutable audit
  events, secrets management, and API rate limits.
- Durable event storage, retention policies, encryption in transit/at rest,
  backup/restore, disaster recovery, and tested migrations.
- Sensor health, ingestion lag, dropped-event counters, clock-skew checks,
  pipeline SLOs, and operational alerting.
- Multi-flow aggregation with explicit event-time windows and late-event rules.
- Calibrated rules, detection tuning, drift monitoring, analyst feedback,
  false-positive workflows, and controlled rule/model changes.
- Independent labelled-traffic evaluation: precision/recall, false positives
  per host/day, latency, throughput, resource use, and robustness.
- Threat-model review, penetration testing, dependency governance, signed
  releases, SBOM, vulnerability response, and deployment security review.
- HA/failover, capacity planning, observability, and documented runbooks.

## Controlled pilot topology

    Zeek / Suricata sensors
             |
             | JSONL export (read-only)
             v
      Isolated ingestion host
             |
             | validate + normalize
             v
      SentinelFlow offline scoring
             |
             | structured alerts
             v
      Restricted analyst review / existing SIEM

Keep existing sensors and SIEM controls authoritative. Run SentinelFlow in
parallel and compare detections before operational reliance.

## Standards and engineering references

- NIST SP 800-207: Zero Trust Architecture.
- NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems.
- OCSF: open schema framework for normalizing cybersecurity events.
- Zeek and Suricata official telemetry documentation.

Standards alignment is a design reference, not a certification claim.
