"""Defensive adapters for Zeek conn.log and Suricata EVE JSONL telemetry."""
from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pandas as pd

from .schema import REQUIRED_COLUMNS


def _number(value: Any, *, default: float = 0.0) -> float:
    if value is None or value == "-":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def _timestamp(value: Any) -> Any:
    # Zeek JSON timestamps are Unix seconds; Suricata commonly emits ISO-8601.
    if isinstance(value, (int, float)):
        return pd.to_datetime(value, unit="s", utc=True)
    return value


def _protocol(value: Any) -> str:
    protocol = str(value or "OTHER").upper()
    return protocol if protocol in {"TCP", "UDP", "ICMP"} else "OTHER"


def _row(*, timestamp: Any, src_ip: Any, dst_ip: Any, protocol: Any,
         duration: Any, src_bytes: Any, dst_bytes: Any, src_packets: Any,
         dst_packets: Any, failed: bool = False, syn_seen: bool = False,
         rst_seen: bool = False) -> dict[str, Any]:
    duration_value = _number(duration)
    source_bytes = _number(src_bytes)
    destination_bytes = _number(dst_bytes)
    packets = _number(src_packets) + _number(dst_packets)
    total_bytes = source_bytes + destination_bytes
    return {
        "timestamp": _timestamp(timestamp), "src_ip": str(src_ip or ""),
        "dst_ip": str(dst_ip or ""), "protocol": _protocol(protocol),
        "duration": duration_value, "src_bytes": source_bytes,
        "dst_bytes": destination_bytes, "packets": packets,
        "failed_connections": int(failed), "unique_dst_ports": 1,
        "mean_packet_size": total_bytes / packets if packets > 0 else 0.0,
        "bytes_per_second": total_bytes / duration_value if duration_value > 0 else 0.0,
        "packets_per_second": packets / duration_value if duration_value > 0 else 0.0,
        "syn_ratio": float(syn_seen), "rst_ratio": float(rst_seen),
        "same_dst_port_ratio": 1.0,
    }


def _zeek(record: Mapping[str, Any]) -> dict[str, Any]:
    state = str(record.get("conn_state", "")).upper()
    return _row(
        timestamp=record.get("ts"), src_ip=record.get("id.orig_h"),
        dst_ip=record.get("id.resp_h"), protocol=record.get("proto"),
        duration=record.get("duration"), src_bytes=record.get("orig_bytes"),
        dst_bytes=record.get("resp_bytes"), src_packets=record.get("orig_pkts"),
        dst_packets=record.get("resp_pkts"),
        failed=state in {"S0", "REJ", "RSTO", "RSTR", "SH"},
        syn_seen=state in {"S0", "S1", "SH"}, rst_seen=state in {"RSTO", "RSTR"},
    )


def _suricata(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("event_type") != "flow":
        return None
    flow = record.get("flow")
    flow_data = flow if isinstance(flow, Mapping) else {}
    state = str(flow_data.get("state", "")).upper()
    return _row(
        timestamp=record.get("timestamp"), src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"), protocol=record.get("proto") or record.get("app_proto"),
        duration=flow_data.get("age"), src_bytes=flow_data.get("bytes_toserver"),
        dst_bytes=flow_data.get("bytes_toclient"),
        src_packets=flow_data.get("pkts_toserver"),
        dst_packets=flow_data.get("pkts_toclient"),
        failed=state in {"NEW", "CLOSED"} and _number(flow_data.get("pkts_toserver")) == 0,
        syn_seen=False, rst_seen=state == "CLOSED",
    )


def iter_jsonl(path: str | Path) -> Iterator[tuple[int, Mapping[str, Any]]]:
    """Yield JSON objects with source line numbers; reject malformed/non-object JSON."""
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"Expected a JSON object on line {line_number}")
            yield line_number, value


def load_sensor_jsonl(path: str | Path, *, source: str) -> pd.DataFrame:
    """Load Zeek JSON conn.log or Suricata EVE JSONL into canonical flow rows."""
    if source not in {"zeek", "suricata"}:
        raise ValueError("source must be 'zeek' or 'suricata'")
    rows: list[dict[str, Any]] = []
    skipped = 0
    for line_number, record in iter_jsonl(path):
        mapped = _zeek(record) if source == "zeek" else _suricata(record)
        if mapped is None:
            skipped += 1
            continue
        rows.append(mapped)
    if not rows:
        raise ValueError(f"No supported {source} flow events found")
    frame = pd.DataFrame(rows, columns=REQUIRED_COLUMNS)
    frame.attrs["skipped_events"] = skipped
    return frame
