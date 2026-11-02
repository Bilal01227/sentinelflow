import json
from argparse import Namespace

import pytest

from sentinelflow.cli import run_csv, run_demo


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
