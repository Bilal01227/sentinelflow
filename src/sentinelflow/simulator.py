"""Deterministic synthetic network-flow generator for safe demos and tests."""
from __future__ import annotations

import numpy as np
import pandas as pd


def generate_flows(rows: int = 5000, *, seed: int = 42, attack_fraction: float = 0.08) -> pd.DataFrame:
    """Generate benign and labelled suspicious flow summaries (no real packets)."""
    if rows < 1:
        raise ValueError("rows must be positive")
    if not 0 <= attack_fraction < 1:
        raise ValueError("attack_fraction must be in [0, 1)")
    rng = np.random.default_rng(seed)
    attacks = rng.random(rows) < attack_fraction
    duration = rng.lognormal(mean=1.5, sigma=0.8, size=rows)
    src_bytes = rng.lognormal(mean=7.0, sigma=1.0, size=rows)
    dst_bytes = rng.lognormal(mean=7.2, sigma=1.0, size=rows)
    packets = np.maximum(1, rng.poisson(18, size=rows))
    failed = rng.poisson(0.15, size=rows)
    ports = rng.integers(1, 5, size=rows)
    syn = rng.beta(2, 12, size=rows)
    rst = rng.beta(1, 20, size=rows)
    for i in np.flatnonzero(attacks):
        kind = rng.choice(["scan", "flood", "bruteforce"], p=[0.4, 0.35, 0.25])
        if kind == "scan":
            duration[i] = rng.uniform(0.01, 1.2)
            ports[i] = rng.integers(12, 90)
            failed[i] = rng.integers(8, 60)
            syn[i] = rng.uniform(0.65, 1.0)
        elif kind == "flood":
            duration[i] = rng.uniform(0.01, 2.0)
            packets[i] = rng.integers(300, 3000)
            src_bytes[i] = rng.uniform(100_000, 2_000_000)
            syn[i] = rng.uniform(0.7, 1.0)
        else:
            failed[i] = rng.integers(10, 100)
            ports[i] = rng.integers(1, 3)
            rst[i] = rng.uniform(0.25, 0.8)
    mean_size = (src_bytes + dst_bytes) / packets
    return pd.DataFrame({
        "timestamp": pd.date_range("2025-01-01", periods=rows, freq="s", tz="UTC"),
        "src_ip": [f"10.0.{x // 254}.{x % 254 + 1}" for x in rng.integers(0, 8 * 254, rows)],
        "dst_ip": [f"192.0.2.{x}" for x in rng.integers(1, 255, rows)],
        "protocol": rng.choice(["TCP", "UDP", "ICMP"], rows, p=[0.75, 0.22, 0.03]),
        "duration": duration, "src_bytes": src_bytes, "dst_bytes": dst_bytes,
        "packets": packets, "failed_connections": failed, "unique_dst_ports": ports,
        "mean_packet_size": mean_size,
        "bytes_per_second": (src_bytes + dst_bytes) / np.maximum(duration, 0.001),
        "packets_per_second": packets / np.maximum(duration, 0.001),
        "syn_ratio": syn, "rst_ratio": rst,
        "same_dst_port_ratio": np.clip(1 - (ports - 1) / 100, 0, 1),
        "label": np.where(attacks, "suspicious", "benign"),
        "scenario": np.where(attacks, "synthetic_attack", "synthetic_benign"),
    })
