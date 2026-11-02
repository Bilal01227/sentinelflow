# Architecture

## Current execution path

```text
Zeek conn.log JSONL / Suricata EVE JSONL / synthetic generator / normalized CSV
                                  |
                                  v
                    source adapter + schema validation
                                  |
                                  v
                        stable feature matrix
                                  |
                                  v
              RobustScaler + IsolationForest anomaly score
                                  |
                     behavioural rule engine
                                  |
                                  v
                  alert + severity + evidence fields
                                  |
                                  v
                       CSV export / JSON metrics
```

## Module boundaries

- integrations.py: offline Zeek and Suricata JSONL adapters.
- simulator.py: deterministic synthetic flow-summary creation; no sockets or packet generation.
- schema.py: canonical schema, IP/time/numeric validation, and stable model feature ordering.
- detector.py: baseline fitting, anomaly scoring, heuristic evidence, and severity aggregation.
- evaluation.py: label-aware metrics, deliberately separate from model fitting.
- cli.py: user-facing commands and artifact output.

## Safety and operational boundaries

- Input is normalized flow metadata; raw packet payloads are not parsed.
- Source event fields are untrusted and validated before model inference.
- Scoring requires a separate baseline file; labelled baselines use only benign rows.
- Model fitting and scoring are offline and in-process. There is no live sensor,
  queue, API server, model registry, or automatic response.
- The adapters map source-specific counters into a simplified schema. Some
  canonical fields are placeholders for a single flow and must not be treated
  as host-level multi-flow statistics.
- No untrusted model artifact is deserialized.

## Design decisions

- Flow summaries, not raw payloads: smaller privacy surface and a clear integration boundary.
- Hybrid detection: explicit rules are inspectable; an unsupervised model can flag deviations.
- Baseline-first fitting: fit on curated benign traffic, separate from evaluation.
- Evidence is data: alerts carry rule identifiers or statistical-outlier evidence.
- Offline by default: no privileged capture, scanning, blocking, or external network activity.

## Planned production extension points

A streaming adapter must define event time, bounded buffering, backpressure,
replay, idempotency, and late-event handling. A service API must add strong
authentication, authorization, rate limiting, audit logs, and retention controls.
See ENTERPRISE_READINESS.md for the production gap checklist.
