# Architecture

## Current execution path

```text
CSV / synthetic flow generator
            |
            v
  schema validation (IP, time, finite values)
            |
            v
       stable feature matrix
            |
            v
 RobustScaler + IsolationForest -----> anomaly score
            |                                  |
            +---- behavioural rules -----------+
                               |
                               v
                alert + severity + evidence
                               |
                   CSV export / JSON metrics
```

## Module boundaries

- `simulator.py`: deterministic synthetic flow-summary creation; no sockets or packet generation.
- `schema.py`: canonical schema, IP/time/numeric validation, and stable model feature ordering.
- `detector.py`: baseline fitting, anomaly scoring, heuristic evidence, and severity aggregation.
- `evaluation.py`: label-aware metrics, deliberately separate from model fitting.
- `cli.py`: user-facing commands and artifact output.

## Safety and operational boundaries

- Input is normalized flow metadata; the program does not parse raw packet payloads.
- CSV input is validated before it reaches the model. Invalid IP addresses, timestamps, protocols, non-finite values, negative values, and out-of-range ratios are rejected or dropped according to strict mode.
- Scoring requires a separate baseline file. If the baseline includes labels, only rows explicitly labelled `benign` are used.
- Model fitting and scoring are currently offline and in-process. There is no live sensor, queue, API server, model registry, or automatic response.
- The model is trained per scoring invocation. No untrusted model artifact is deserialized.

## Design decisions

- **Flow summaries, not raw payloads:** smaller privacy surface and a clear integration boundary for exporters.
- **Hybrid detection:** explicit rules are inspectable; an unsupervised model can flag deviations not covered by those rules.
- **Baseline-first fitting:** fit on a curated, representative benign period, separate from the evaluation period.
- **Evidence is data:** each alert carries rule identifiers or a statistical-outlier reason, not only a binary prediction.
- **Offline by default:** no privileged capture, scanning, blocking, or external network activity.

## Planned extension points

A future exporter adapter should map its schema into the canonical flow contract. A streaming adapter must define event time, bounded buffering, backpressure, retry behaviour, and duplicate handling. A service API must add authentication, authorization, rate limiting, audit logs, and retention controls before exposure.
