# Architecture

## Current execution path

```text
CSV / synthetic flow generator
            |
            v
      schema.validate
            |
            v
       feature_matrix
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
- `schema.py`: canonical schema, validation, and stable model feature ordering.
- `detector.py`: baseline fitting, anomaly scoring, heuristic evidence, and severity aggregation.
- `evaluation.py`: label-aware metrics, deliberately separate from model fitting.
- `cli.py`: user-facing commands and artifact output.

## Design decisions

- **Flow summaries, not raw payloads:** a smaller privacy surface and a clear integration boundary for Zeek or another exporter later.
- **Hybrid detection:** explicit rules are inspectable; an unsupervised model can flag deviations not covered by those rules.
- **Baseline-first fitting:** the model should learn a known representative benign period. Mixed labelled synthetic input is only used by the demo to simplify reproducibility.
- **Evidence is data:** each alert carries rule identifiers or a statistical-outlier reason, not only a binary prediction.
- **Offline by default:** no privileged capture, scanning, blocking, or external network activity.

## Planned extension points

A future adapter should map an exporter schema into the canonical flow contract. A streaming adapter should preserve event time, bounded buffering, backpressure, and explicit failure handling. A dashboard should consume exported event records rather than duplicating detection logic.
