import json
from argparse import Namespace

from sentinelflow.cli import run_demo


def test_demo_writes_events_and_metrics(tmp_path):
    output = tmp_path / "nested" / "events.csv"
    code = run_demo(Namespace(rows=180, seed=3, attack_fraction=0.1,
                              contamination=0.05, output=str(output)))
    assert code == 0
    assert output.exists()
    report = json.loads(output.with_suffix(".metrics.json").read_text())
    assert report["rows"] == 180
    assert "caveat" in report
