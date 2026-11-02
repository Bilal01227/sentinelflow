import pytest

from sentinelflow.detector import SentinelDetector
from sentinelflow.evaluation import evaluate
from sentinelflow.simulator import generate_flows


def test_detector_requires_fit():
    data = generate_flows(40)
    with pytest.raises(RuntimeError):
        SentinelDetector().predict(data)


def test_detector_returns_explanations_and_alert_fields():
    data = generate_flows(600, seed=9, attack_fraction=0.12)
    baseline = data[data.label == "benign"]
    result = SentinelDetector().fit(baseline).predict(data)
    for field in ("is_alert", "severity", "evidence", "anomaly_score", "model_anomaly"):
        assert field in result.events
    assert result.events["is_alert"].any()
    assert result.events.loc[result.events.is_alert, "evidence"].ne("none").all()


def test_evaluation_metrics_are_bounded():
    data = generate_flows(200, seed=11)
    result = SentinelDetector().fit(data[data.label == "benign"]).predict(data)
    metrics = evaluate(result.events, data.label)
    assert 0 <= metrics["precision"] <= 1
    assert 0 <= metrics["recall"] <= 1
    assert len(metrics["confusion_matrix"]) == 2


def test_invalid_contamination_rejected():
    with pytest.raises(ValueError):
        SentinelDetector(contamination=0.8)


def test_detector_rejects_empty_scoring_batch():
    data = generate_flows(30)
    detector = SentinelDetector().fit(data[data.label == "benign"])
    with pytest.raises(ValueError, match="empty flow"):
        detector.predict(data.iloc[0:0])


def test_detector_requires_minimum_baseline():
    data = generate_flows(19)
    with pytest.raises(ValueError, match="At least 20"):
        SentinelDetector().fit(data)


def test_detector_rejects_contaminated_labelled_baseline():
    data = generate_flows(100, attack_fraction=0.2)
    with pytest.raises(ValueError, match="only benign-labelled"):
        SentinelDetector().fit(data)
