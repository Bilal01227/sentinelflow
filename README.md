# SentinelFlow

**An explainable, reproducible network-flow intrusion detection research toolkit.**

SentinelFlow combines transparent behavioural rules with an Isolation Forest anomaly model. It ingests normalized flow summaries, validates the schema, scores suspicious behaviour, records human-readable evidence, and exports analyst-friendly CSV and JSON results. A deterministic synthetic traffic generator makes the project runnable without packet captures, privileged network access, or third-party datasets.

> **Status: Alpha / research prototype.** SentinelFlow is not a production network sensor, inline blocker, SIEM replacement, or guarantee of attack detection. The included simulator is synthetic and its metrics are not evidence of real-world performance.

## Why this project exists

Many small IDS demonstrations either show a black-box model or rely on a single labelled dataset. SentinelFlow is designed around a different engineering principle: make ingestion, validation, detection evidence, and evaluation independently inspectable. It is an original implementation; established IDS and ML projects are useful architectural references, not code dependencies or copied implementations.

## Capabilities

- **Safe flow-summary interface:** normalized CSV input; no packet payload execution or automatic network scanning.
- **Strict schema validation:** timestamp, protocol, numeric, missing-value, and negative-value checks.
- **Hybrid detection:** explicit behavioural rules plus unsupervised Isolation Forest scoring.
- **Explainable alerts:** rule identifiers, severity, anomaly score, and analyst-readable reason per flow.
- **Reproducible simulation:** seeded synthetic benign and suspicious flows, including scan-like, flood-like, and repeated-failure patterns.
- **Honest evaluation:** precision, recall, F1, confusion matrix, and machine-readable report when labels are available.
- **CLI-first workflow:** easy to automate, test, and integrate into a future dashboard or streaming adapter.

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
pytest
sentinelflow demo --rows 5000 --seed 42
```

The demo writes:

- `artifacts/demo-events.csv` — one scored record per flow.
- `artifacts/demo-events.metrics.json` — summary, evaluation metrics, and limitations.

Run `sentinelflow --help` or `sentinelflow score --help` for command options.

## Input CSV contract

The `score` command accepts a normalized flow CSV with these columns:

| Column | Meaning |
|---|---|
| `timestamp` | Flow timestamp; parseable as a date/time |
| `src_ip`, `dst_ip` | Source and destination address strings |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `OTHER` |
| `duration` | Flow duration in seconds |
| `src_bytes`, `dst_bytes` | Bytes in each direction |
| `packets` | Total packets in the flow |
| `failed_connections` | Failed connection attempts attributed to the flow/window |
| `unique_dst_ports` | Distinct destination ports observed in the aggregation window |
| `mean_packet_size` | Mean packet size in bytes |
| `bytes_per_second`, `packets_per_second` | Rates computed by the upstream flow exporter |
| `syn_ratio`, `rst_ratio` | Ratios in the interval [0, 1] |
| `same_dst_port_ratio` | Ratio in the interval [0, 1] |

Example:

```bash
sentinelflow score --input flows.csv --baseline benign-baseline.csv --output scored.csv
```

If `--baseline` is omitted, the input itself is used for fitting. That is convenient for a quick experiment but **not a sound deployment procedure**: provide a curated, representative benign baseline separated by time and environment. Do not train on the same evaluation period if you intend to report generalization.

## Detection design

1. Validate and normalize flow summaries.
2. Fit robust scaling and Isolation Forest on a designated baseline.
3. Calculate anomaly scores for each flow.
4. Apply explicit rules for port-scan-like fan-out, high packet-rate bursts, repeated failures, and high SYN ratios.
5. Combine model outliers and rule hits into alerts, retaining the evidence that caused each alert.
6. Evaluate against labels only when a ground-truth label column is available.

The rules are heuristics, not universal thresholds. Network role, traffic volume, sampling method, and flow exporter semantics affect their usefulness. Tune and document thresholds for each environment.

## Security and privacy

- Use sanitized, authorized flow metadata only.
- Do not commit packet captures, customer data, secrets, API keys, or private IP inventories.
- Treat imported CSV files as untrusted input and keep them within approved storage boundaries.
- The project currently scores offline files; it does not sniff interfaces, modify firewall rules, or block traffic.
- Review `SECURITY.md` before reporting a vulnerability.

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest --cov=sentinelflow --cov-report=term-missing
```

See [architecture](docs/ARCHITECTURE.md), [evaluation protocol](docs/EVALUATION.md), and [roadmap](docs/ROADMAP.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md). Streaming ingestion, PCAP/Zeek adapters, dashboard, model persistence, drift monitoring, and calibrated thresholds are intentionally not claimed as implemented yet.

## Citation

If you use SentinelFlow in academic or engineering work, cite the repository URL and the exact release or commit you used. Results should include dataset provenance, train/test split, environment, threshold configuration, and baseline comparison.

## License

MIT. See [LICENSE](LICENSE).
