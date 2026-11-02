# Roadmap

## Implemented in 0.2.0

- [x] Canonical IPv4/IPv6 flow-summary schema and validation
- [x] Finite numeric and ratio validation; duplicate-column rejection
- [x] Deterministic synthetic flow generator
- [x] Separate-baseline Isolation Forest scoring
- [x] Transparent heuristic evidence and severity aggregation
- [x] Offline CLI and label-aware synthetic evaluation
- [x] Tests, CI, CodeQL, formatting, and dependency audit

## Required before production IDS deployment

- [ ] Zeek JSON/TSV adapter with schema mapping tests
- [ ] PCAP-to-flow adapter using a documented parser
- [ ] Streaming ingestion with bounded queues, backpressure, and retry policy
- [ ] Trusted model artifact format, signed provenance, and model registry
- [ ] Threshold calibration on representative production traffic
- [ ] Drift monitoring and retraining approval workflow
- [ ] Rule-only / model-only / hybrid external benchmark
- [ ] Alert deduplication, rate limiting, and analyst triage lifecycle
- [ ] Authenticated API, authorization, audit logs, and retention controls
- [ ] Container hardening, deployment manifests, health checks, and observability
- [ ] Disaster recovery, performance/load tests, and security review

Do not mark an item complete until implementation, tests, documentation, and operational evidence are merged.
