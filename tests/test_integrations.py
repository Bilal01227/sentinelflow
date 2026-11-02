import json

import pytest

from sentinelflow.integrations import load_sensor_jsonl
from sentinelflow.schema import validate_flows


def test_zeek_conn_log_jsonl_maps_and_validates(tmp_path):
    source = tmp_path / "conn.jsonl"
    record = {
        "ts": "2026-01-01T00:00:00Z", "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.20", "proto": "tcp", "duration": 2.0,
        "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 2,
        "resp_pkts": 3, "conn_state": "S0",
    }
    source.write_text(json.dumps(record) + "\n", encoding="utf-8")
    clean, report = validate_flows(load_sensor_jsonl(source, source="zeek"), strict=True)
    assert report.rows == 1
    assert clean.loc[0, "packets"] == 5
    assert clean.loc[0, "failed_connections"] == 1
    assert clean.loc[0, "syn_ratio"] == 1


def test_suricata_eve_skips_non_flow_and_maps_flow(tmp_path):
    source = tmp_path / "eve.json"
    events = [
        {"event_type": "alert", "src_ip": "192.0.2.1"},
        {
            "timestamp": "2026-01-01T00:00:00Z", "event_type": "flow",
            "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20", "proto": "TCP",
            "flow": {"age": 4, "bytes_toserver": 400, "bytes_toclient": 200,
                     "pkts_toserver": 4, "pkts_toclient": 2, "state": "established"},
        },
    ]
    source.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    clean, _ = validate_flows(load_sensor_jsonl(source, source="suricata"), strict=True)
    assert len(clean) == 1
    assert clean.loc[0, "bytes_per_second"] == 150


def test_invalid_jsonl_fails_with_line_number(tmp_path):
    source = tmp_path / "broken.jsonl"
    source.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        load_sensor_jsonl(source, source="zeek")


def test_unsupported_source_rejected(tmp_path):
    source = tmp_path / "empty.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source must"):
        load_sensor_jsonl(source, source="unknown")
