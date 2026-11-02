"""Hybrid rule + unsupervised anomaly detector with human-readable evidence."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler

from .schema import feature_matrix

RULES = {
    "possible_port_scan": ("unique_dst_ports", 12.0, "high"),
    "possible_connection_flood": ("packets_per_second", 250.0, "critical"),
    "repeated_connection_failures": ("failed_connections", 8.0, "medium"),
    "high_syn_ratio": ("syn_ratio", 0.65, "high"),
}
SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DetectionResult:
    events: pd.DataFrame
    model: IsolationForest
    contamination: float


class SentinelDetector:
    """Fit on a representative baseline, then score flow summaries."""

    def __init__(self, *, contamination: float = 0.04, random_state: int = 42) -> None:
        if not 0.001 <= contamination <= 0.5:
            raise ValueError("contamination must be between 0.001 and 0.5")
        self.contamination = contamination
        self.random_state = random_state
        self.model = make_pipeline(
            RobustScaler(),
            IsolationForest(n_estimators=250, contamination=contamination,
                            random_state=random_state, n_jobs=-1),
        )
        self._fitted = False

    def fit(self, baseline: pd.DataFrame) -> "SentinelDetector":
        if len(baseline) < 20:
            raise ValueError("At least 20 baseline flows are required")
        self.model.fit(feature_matrix(baseline))
        self._fitted = True
        return self

    def predict(self, flows: pd.DataFrame) -> DetectionResult:
        if not self._fitted:
            raise RuntimeError("Call fit() before predict()")
        x = feature_matrix(flows)
        raw = self.model.decision_function(x)
        anomaly = self.model.predict(x) == -1
        records = flows.reset_index(drop=True).copy()
        records["anomaly_score"] = -raw
        records["model_anomaly"] = anomaly
        evidence: list[list[str]] = [[] for _ in range(len(records))]
        severity = np.full(len(records), "low", dtype=object)
        for name, (column, threshold, level) in RULES.items():
            hits = records[column].to_numpy(dtype=float) >= threshold
            for idx in np.flatnonzero(hits):
                evidence[idx].append(name)
                if SEVERITY_SCORE[level] > SEVERITY_SCORE[str(severity[idx])]:
                    severity[idx] = level
        for idx in np.flatnonzero(anomaly):
            if not evidence[idx]:
                evidence[idx].append("statistical_outlier_review")
        rule_hit = np.array([bool(x) for x in evidence])
        records["is_alert"] = rule_hit | anomaly
        records["severity"] = severity
        records.loc[anomaly & (records["severity"] == "low"), "severity"] = "medium"
        records["evidence"] = [";".join(x) if x else "none" for x in evidence]
        records["alert_reason"] = records["evidence"].map(
            lambda value: value.replace("_", " ").replace(";", ", ")
        )
        return DetectionResult(records, self.model, self.contamination)
