# Changelog

## 0.2.0

- Require a separate benign baseline for offline CSV scoring.
- Validate IPv4/IPv6 addresses, finite numeric features, duplicate columns, timestamps, protocols, and ratio bounds.
- Fail closed when validation produces no usable rows or scoring receives an empty batch.
- Expand regression tests and CI with Python 3.10–3.13, coverage threshold, CodeQL, and dependency auditing.
- Clarify alpha status and the operational work still required before a production network IDS deployment.

## 0.1.0

- Initial alpha release with synthetic flow generation, Isolation Forest, behavioural heuristics, CLI, and evaluation metrics.
