import json
from argparse import Namespace

import pytest

from sentinelflow.cli import run_csv, run_demo, run_ingest


def test_demo_writes_events_and_metrics(tmp_path):
    output = tmp_path / "nested" / "events.csv"
    code = run_demo(
        Namespace(
            rows=180,
            seed=3,
            attack_fraction=0.1,
            contamination=0.05,
            output=str(output),
        )
    )
    assert code == 0
    assert output.exists()
    report = json.loads(output.with_suffix(".metrics.json").read_text())
    assert report["rows"] == 180
    assert "caveat" in report


def test_csv_scoring_requires_separate_baseline():
    args = Namespace(
        input="ignored.csv",
        baseline=None,
        output="out.csv",
        contamination=0.04,
        strict=False,
    )
    with pytest.raises(ValueError, match="separate benign --baseline"):
        run_csv(args)


def test_run_ingest_writes_normalized_csv(tmp_path):
    source = tmp_path / "conn.jsonl"
    record = {
        "ts": "2026-01-01T00:00:00Z", "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.20", "proto": "tcp", "duration": 2,
        "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 2,
        "resp_pkts": 3, "conn_state": "SF",
    }
    source.write_text(json.dumps(record) + "\\n", encoding="utf-8")
    output = tmp_path / "nested" / "flows.csv"
    code = run_ingest(
        Namespace(source="zeek", input=str(source), output=str(output), strict=False)
    )
    assert code == 0
    assert output.exists()
