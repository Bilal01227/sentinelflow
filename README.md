# SentinelFlow

**Explainable network-flow intrusion detection and telemetry normalization toolkit.**

SentinelFlow validates network-flow records, ingests exported Zeek and Suricata telemetry, fits an anomaly detector against a separate benign baseline, applies transparent behavioural heuristics, and emits structured alerts with evidence.

> **Release status: alpha / controlled-pilot engineering build.** SentinelFlow is not a validated production NIDS, inline prevention system, SIEM replacement, or guarantee of attack detection. It does not capture packets, perform live streaming, or autonomously block traffic. Production reliance requires independent validation and the controls documented in [Enterprise readiness](docs/ENTERPRISE_READINESS.md).

## Capabilities

- Offline JSONL adapters for Zeek conn.log and Suricata EVE flow events.
- Strict normalized flow schema validation, including IP address, timestamp, finite numeric, ratio, and protocol checks.
- Isolation Forest anomaly scoring with robust feature scaling.
- Explainable heuristic signals for scan-like fan-out, high packet-rate bursts, repeated failures, and high SYN ratios.
- Structured alert records with severity, anomaly score, and evidence identifiers.
- Deterministic synthetic traffic generator and label-aware evaluation.
- CLI for ingestion, reproducible demos, and offline CSV scoring.
- CI across Python 3.10–3.13, CodeQL analysis, dependency audit, and coverage gate.

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
pytest --cov=sentinelflow --cov-report=term-missing
sentinelflow demo --rows 5000 --seed 42
```

The demo writes scored CSV and JSON metrics under artifacts/. Metrics are synthetic demonstration results, not real-world performance evidence.

## Ingest sensor telemetry

Zeek JSON conn.log:

```bash
sentinelflow ingest --source zeek --input conn.log --output artifacts/zeek-flows.csv
```

Suricata EVE JSONL (flow events):

```bash
sentinelflow ingest --source suricata --input eve.json --output artifacts/suricata-flows.csv
```

Then score normalized flows against a separate representative benign baseline:

```bash
sentinelflow score --input artifacts/zeek-flows.csv --baseline benign-baseline.csv --output artifacts/alerts.csv
```

See [sensor ingestion details](docs/INGESTION.md) for field mappings, caveats, and source-format references.

## Canonical flow fields

| Field | Meaning |
|---|---|
| timestamp | Parseable flow timestamp |
| src_ip, dst_ip | IPv4 or IPv6 address |
| protocol | TCP, UDP, ICMP, or OTHER |
| duration | Duration in seconds |
| src_bytes, dst_bytes | Bytes in each direction |
| packets | Total packets |
| failed_connections | Failed connections attributed to the flow/window |
| unique_dst_ports | Distinct destination ports in aggregation window |
| mean_packet_size | Mean packet size |
| bytes_per_second, packets_per_second | Rates computed by upstream exporter |
| syn_ratio, rst_ratio, same_dst_port_ratio | Ratios in [0, 1] |

## Operational guidance

- Use only authorized flow metadata and approved storage.
- Build the benign baseline from a representative historical period, excluding known incidents and contaminated traffic.
- Keep training, threshold selection, and evaluation periods separate.
- Calibrate rule thresholds for network role and exporter semantics; defaults are illustrative.
- Treat anomaly scores as review signals, not proof of malicious intent.
- Restrict access to input and output files because flow records can be sensitive.
- Do not load model artifacts from untrusted sources; this release does not deserialize external model files.
- Run as a least-privileged user in an isolated environment.

## Engineering documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Sensor ingestion](docs/INGESTION.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Enterprise readiness and production gap analysis](docs/ENTERPRISE_READINESS.md)
- [Security policy](SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT. See [LICENSE](LICENSE).
