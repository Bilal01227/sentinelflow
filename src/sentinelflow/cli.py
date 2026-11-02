"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .detector import SentinelDetector
from .evaluation import evaluate
from .schema import validate_flows
from .simulator import generate_flows


def run_demo(args: argparse.Namespace) -> int:
    raw = generate_flows(args.rows, seed=args.seed, attack_fraction=args.attack_fraction)
    flows, report = validate_flows(raw)
    baseline = flows.loc[flows["label"] == "benign"]
    detector = SentinelDetector(contamination=args.contamination).fit(baseline)
    result = detector.predict(flows)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.events.to_csv(output, index=False)
    metrics = evaluate(result.events, flows["label"])
    summary = {
        "rows": len(flows), "dropped_rows": report.dropped_rows,
        "alerts": int(result.events["is_alert"].sum()),
        "severity_counts": result.events.loc[result.events["is_alert"], "severity"].value_counts().to_dict(),
        "metrics": metrics,
        "caveat": "Synthetic demonstration only; not a validated production IDS benchmark.",
    }
    metrics_path = output.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nEvents: {output}\nMetrics: {metrics_path}")
    return 0


def run_csv(args: argparse.Namespace) -> int:
    raw = pd.read_csv(args.input)
    flows, report = validate_flows(raw, strict=args.strict)
    baseline = flows if args.baseline is None else validate_flows(pd.read_csv(args.baseline))[0]
    detector = SentinelDetector(contamination=args.contamination).fit(baseline)
    result = detector.predict(flows)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    result.events.to_csv(args.output, index=False)
    print(f"Scored {len(flows)} flows; dropped {report.dropped_rows}; alerts {int(result.events.is_alert.sum())}")
    for warning in report.warnings:
        print(f"WARNING: {warning}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinelflow", description="Network-flow intrusion detection research toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run a reproducible synthetic demonstration")
    demo.add_argument("--rows", type=int, default=5000)
    demo.add_argument("--seed", type=int, default=42)
    demo.add_argument("--attack-fraction", type=float, default=0.08)
    demo.add_argument("--contamination", type=float, default=0.04)
    demo.add_argument("--output", default="artifacts/demo-events.csv")
    demo.set_defaults(func=run_demo)
    score = sub.add_parser("score", help="score a CSV of normalized flow records")
    score.add_argument("--input", required=True)
    score.add_argument("--baseline", help="optional benign baseline CSV; defaults to input")
    score.add_argument("--output", default="artifacts/scored-events.csv")
    score.add_argument("--contamination", type=float, default=0.04)
    score.add_argument("--strict", action="store_true")
    score.set_defaults(func=run_csv)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
