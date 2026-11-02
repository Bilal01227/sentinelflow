"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .detector import SentinelDetector
from .evaluation import evaluate
from .integrations import load_sensor_jsonl
from .schema import validate_flows
from .simulator import generate_flows


def run_demo(args: argparse.Namespace) -> int:
    raw = generate_flows(args.rows, seed=args.seed, attack_fraction=args.attack_fraction)
    flows, report = validate_flows(raw, strict=True)
    baseline = flows.loc[flows["label"] == "benign"]
    detector = SentinelDetector(contamination=args.contamination).fit(baseline)
    result = detector.predict(flows)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.events.to_csv(output, index=False)
    metrics = evaluate(result.events, flows["label"])
    severity_counts = (\n        result.events.loc[result.events["is_alert"], "severity"].value_counts().to_dict()\n    )
    summary = {
        "rows": len(flows), "dropped_rows": report.dropped_rows,
        "alerts": int(result.events["is_alert"].sum()), "severity_counts": severity_counts,
        "metrics": metrics,
        "caveat": "Synthetic demonstration only; not a validated production IDS benchmark.",
    }
    metrics_path = output.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nEvents: {output}\nMetrics: {metrics_path}")
    return 0


def run_ingest(args: argparse.Namespace) -> int:
    raw = load_sensor_jsonl(args.input, source=args.source)
    flows, report = validate_flows(raw, strict=args.strict)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    flows.to_csv(output, index=False)
    skipped = int(raw.attrs.get("skipped_events", 0))
    print(
        f"Ingested {len(flows)} {args.source} flow records; "
        f"skipped non-flow events {skipped}; dropped invalid rows {report.dropped_rows}; "
        f"output {output}"
    )
    for warning in report.warnings:
        print(f"WARNING: {warning}")
    return 0


def run_csv(args: argparse.Namespace) -> int:
    if args.baseline is None:
        raise ValueError(
            "A separate benign --baseline CSV is required for scoring. "
            "Use 'sentinelflow demo' for a synthetic demonstration."
        )
    raw = pd.read_csv(args.input)
    baseline_raw = pd.read_csv(args.baseline)
    flows, report = validate_flows(raw, strict=args.strict)
    baseline, baseline_report = validate_flows(baseline_raw, strict=True)
    if "label" in baseline.columns:
        baseline = baseline.loc[baseline["label"].astype(str).str.lower() == "benign"]
    detector = SentinelDetector(contamination=args.contamination).fit(baseline)
    result = detector.predict(flows)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.events.to_csv(output, index=False)
    print(
        f"Scored {len(flows)} flows; dropped {report.dropped_rows}; "
        f"alerts {int(result.events['is_alert'].sum())}; baseline rows {len(baseline)}."
    )
    for warning in (*report.warnings, *baseline_report.warnings):
        print(f"WARNING: {warning}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinelflow", description="Explainable network-flow intrusion detection toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run a reproducible synthetic demonstration")
    demo.add_argument("--rows", type=int, default=5000)
    demo.add_argument("--seed", type=int, default=42)
    demo.add_argument("--attack-fraction", type=float, default=0.08)
    demo.add_argument("--contamination", type=float, default=0.04)
    demo.add_argument("--output", default="artifacts/demo-events.csv")
    demo.set_defaults(func=run_demo)
    ingest = sub.add_parser("ingest", help="normalize Zeek or Suricata JSONL flow telemetry")
    ingest.add_argument("--source", choices=("zeek", "suricata"), required=True)
    ingest.add_argument("--input", required=True)
    ingest.add_argument("--output", default="artifacts/ingested-flows.csv")
    ingest.add_argument("--strict", action="store_true")
    ingest.set_defaults(func=run_ingest)
    score = sub.add_parser("score", help="score a CSV against a separate benign baseline")
    score.add_argument("--input", required=True)
    score.add_argument(\n        "--baseline", required=True, help="separate representative benign baseline CSV"\n    )
    score.add_argument("--output", default="artifacts/scored-events.csv")
    score.add_argument("--contamination", type=float, default=0.04)
    score.add_argument("--strict", action="store_true")
    score.set_defaults(func=run_csv)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
