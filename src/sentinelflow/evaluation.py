"""Evaluation helpers; metrics are computed only when ground truth is supplied."""
from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def evaluate(events: pd.DataFrame, labels: pd.Series) -> dict[str, Any]:
    if len(events) != len(labels):
        raise ValueError("events and labels must have equal lengths")
    truth = labels.astype(str).str.lower().isin(
        ["1", "true", "attack", "suspicious", "malicious"]
    )
    pred = events["is_alert"].astype(bool)
    return {
        "precision": float(precision_score(truth, pred, zero_division=0)),
        "recall": float(recall_score(truth, pred, zero_division=0)),
        "f1": float(f1_score(truth, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(truth, pred, labels=[False, True]).tolist(),
        "classification_report": classification_report(
            truth, pred, zero_division=0, output_dict=True
        ),
    }
