"""Canonical flow schema and safe input validation."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import numpy as np
import pandas as pd

NUMERIC_FEATURES = (
    "duration",
    "src_bytes",
    "dst_bytes",
    "packets",
    "failed_connections",
    "unique_dst_ports",
    "mean_packet_size",
    "bytes_per_second",
    "packets_per_second",
    "syn_ratio",
    "rst_ratio",
    "same_dst_port_ratio",
)
REQUIRED_COLUMNS = ("timestamp", "src_ip", "dst_ip", "protocol", *NUMERIC_FEATURES)


@dataclass(frozen=True)
class ValidationReport:
    rows: int
    dropped_rows: int
    warnings: tuple[str, ...]


def _valid_ip(value: object) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def validate_flows(
    frame: pd.DataFrame, *, strict: bool = False
) -> tuple[pd.DataFrame, ValidationReport]:
    """Validate normalized IP flow records and reject malformed numeric values."""
    if frame.columns.duplicated().any():
        raise ValueError("Duplicate CSV column names are not allowed")
    missing = sorted(set(REQUIRED_COLUMNS) - set(frame.columns))
    if missing:
        raise ValueError(f"Missing required flow columns: {', '.join(missing)}")
    optional_columns = [column for column in ("label", "scenario") if column in frame.columns]
    data = frame.loc[:, [*REQUIRED_COLUMNS, *optional_columns]].copy()
    warnings: list[str] = []
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce", utc=True)
    for column in NUMERIC_FEATURES:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data["protocol"] = data["protocol"].astype("string").str.upper().str.strip()
    for column in ("src_ip", "dst_ip"):
        data[column] = data[column].astype("string").str.strip()
    invalid = data[list(REQUIRED_COLUMNS)].isna().any(axis=1)
    numeric = data.loc[:, NUMERIC_FEATURES].to_numpy(dtype=float)
    invalid |= ~np.isfinite(numeric).all(axis=1)
    invalid |= (data[list(NUMERIC_FEATURES)] < 0).any(axis=1)
    invalid |= ~data["protocol"].isin(["TCP", "UDP", "ICMP", "OTHER"])
    invalid |= ~data["src_ip"].map(_valid_ip)
    invalid |= ~data["dst_ip"].map(_valid_ip)
    for ratio_column in ("syn_ratio", "rst_ratio", "same_dst_port_ratio"):
        invalid |= ~data[ratio_column].between(0.0, 1.0, inclusive="both")
    dropped = int(invalid.sum())
    if dropped:
        warnings.append(f"Dropped {dropped} malformed or negative-valued flow rows.")
        if strict:
            raise ValueError(warnings[-1])
        data = data.loc[~invalid].copy()
    if data.empty:
        raise ValueError("No valid flow rows remain after validation")
    data = data.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return data, ValidationReport(rows=len(data), dropped_rows=dropped, warnings=tuple(warnings))


def feature_matrix(frame: pd.DataFrame) -> pd.DataFrame:
    """Return finite numeric model features in a stable order."""
    missing = set(NUMERIC_FEATURES) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing model features: {', '.join(sorted(missing))}")
    result = frame.loc[:, NUMERIC_FEATURES].astype(float)
    values = result.to_numpy()
    if not np.isfinite(values).all():
        raise ValueError("Model features must contain only finite numeric values")
    return result
