# SentinelFlow

**Explainable network-flow intrusion detection research toolkit.**

SentinelFlow validates normalized IP flow records, fits an anomaly detector against a separate benign baseline, applies transparent behavioural heuristics, and emits structured alerts with evidence.

> **Release status: alpha.** SentinelFlow is not a validated production network IDS, inline prevention system, SIEM replacement, or guarantee of attack detection. It has no native packet capture, streaming sensor, high-availability deployment, or externally validated model benchmark. Do not deploy it as a security control without environment-specific validation and operational review.

## Implemented

- Strict normalized flow schema validation, including IP address, timestamp, finite numeric, ratio, and protocol checks.
- Isolation Forest anomaly scoring with robust feature scaling.
- Explainable heuristic signals for scan-like fan-out, high packet-rate bursts, repeated failures, and high SYN ratios.
- Structured alert records with severity, anomaly score, and evidence identifiers.
- Deterministic synthetic traffic generator and label-aware evaluation.
- CLI for reproducible demos and offline CSV scoring.
- Automated test, formatting, static analysis, and dependency-audit workflows.

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Bilal01227/sentinelflow.git
cd sentinelflow
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest --cov=sentinelflow --cov-report=term-missing
sentinelflow demo --rows 5000 --seed 42
```

The demo writes scored CSV and JSON metrics under `artifacts/`. Its metrics are synthetic demonstration results, not real-world performance evidence.

## Score real flow summaries

Scoring requires a **separate representative benign baseline**. This avoids the previous unsafe default of fitting on the same data being scored.

```bash
sentinelflow score --input evaluation-flows.csv --baseline benign-baseline.csv --output artifacts/alerts.csv
```

Both files must contain the normalized columns below. If the baseline contains a `label` column, only rows labelled `benign` are used.

| Column | Meaning |
|---|---|
| `timestamp` | Parseable flow timestamp |
| `src_ip`, `dst_ip` | IPv4 or IPv6 address |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `OTHER` |
| `duration` | Duration in seconds |
| `src_bytes`, `dst_bytes` | Bytes in each direction |
| `packets` | Total packets |
| `failed_connections` | Failed connections attributed to the flow/window |
| `unique_dst_ports` | Distinct destination ports in the aggregation window |
| `mean_packet_size` | Mean packet size |
| `bytes_per_second`, `packets_per_second` | Rates computed by the upstream exporter |
| `syn_ratio`, `rst_ratio`, `same_dst_port_ratio` | Ratios in [0, 1] |

Malformed rows are rejected in strict mode; non-strict validation drops malformed rows and reports the count. Empty or invalid batches fail closed with an error.

## Operational guidance

- Use only authorized flow metadata and approved storage.
- Build the benign baseline from a representative historical period, excluding known incidents and contaminated traffic.
- Keep training, threshold selection, and evaluation periods separate.
- Calibrate rule thresholds for the network role and exporter semantics; defaults are illustrative.
- Treat anomaly scores as review signals, not proof of malicious intent.
- Restrict access to input and output files because IP flow records can be sensitive.
- Do not load model artifacts from untrusted sources. The current release does not deserialize externally supplied model files.
- Run as a least-privileged user in an isolated environment. The CLI does not capture packets, scan hosts, or modify firewall rules.

## Architecture and evaluation

- [Architecture](docs/ARCHITECTURE.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Security policy](SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## What is not production-ready yet

Native Zeek/PCAP ingestion, streaming/backpressure, persistent trusted model registry, drift monitoring, calibrated thresholds, alert deduplication, authenticated API, dashboards, high availability, deployment manifests, and independent real-network evaluation are not implemented. These are explicit roadmap items—not features to infer from the current CLI.

## License

MIT. See [LICENSE](LICENSE).
