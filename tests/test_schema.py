import numpy as np
import pandas as pd
import pytest

from sentinelflow.schema import NUMERIC_FEATURES, feature_matrix, validate_flows
from sentinelflow.simulator import generate_flows


def test_simulator_is_reproducible():
    pd.testing.assert_frame_equal(generate_flows(100, seed=7), generate_flows(100, seed=7))


def test_validation_drops_malformed_rows():
    data = generate_flows(30)
    data.loc[0, "packets"] = -1
    clean, report = validate_flows(data)
    assert len(clean) == 29
    assert report.dropped_rows == 1


def test_strict_validation_rejects_bad_rows():
    data = generate_flows(30)
    data.loc[0, "protocol"] = "TELNET-UNKNOWN"
    with pytest.raises(ValueError):
        validate_flows(data, strict=True)


def test_feature_matrix_has_stable_columns():
    data = generate_flows(25)
    assert list(feature_matrix(data).columns) == list(NUMERIC_FEATURES)


def test_validation_rejects_ratio_outside_unit_interval():
    data = generate_flows(30)
    data.loc[0, "syn_ratio"] = 1.5
    clean, report = validate_flows(data)
    assert len(clean) == 29
    assert report.dropped_rows == 1


def test_validation_rejects_invalid_ip_and_infinite_features():
    data = generate_flows(30)
    data.loc[0, "src_ip"] = "not-an-ip"
    data.loc[1, "bytes_per_second"] = np.inf
    clean, report = validate_flows(data)
    assert len(clean) == 28
    assert report.dropped_rows == 2


def test_validation_rejects_empty_result():
    data = generate_flows(20)
    data["src_ip"] = "invalid"
    with pytest.raises(ValueError, match="No valid flow rows"):
        validate_flows(data)


def test_duplicate_columns_rejected():
    data = generate_flows(20)
    data.columns = [*data.columns[:-1], "label"]
    with pytest.raises(ValueError, match="Duplicate CSV"):
        validate_flows(data)


def test_count_features_must_be_integers():
    data = generate_flows(30)
    data.loc[0, "packets"] = 1.5
    clean, report = validate_flows(data)
    assert len(clean) == 29
    assert report.dropped_rows == 1
