# Evaluation protocol

## What the built-in demo measures

The simulator produces reproducible synthetic benign and suspicious flow summaries. The CLI reports precision, recall, F1, and a confusion matrix by comparing the combined alert decision with the synthetic label.

These values measure behaviour on the simulator's own generated patterns. They are **not** a benchmark, a claim about real networks, or a substitute for an independently collected test set.

## Required protocol before making external performance claims

1. Record dataset name, version, license, collection period, feature definitions, and preprocessing.
2. Split chronologically or by host/site to prevent leakage between train and test.
3. Fit scalers and anomaly models on a designated benign training baseline only.
4. Keep validation data separate for threshold selection.
5. Report per-class precision/recall/F1, confusion matrix, false-positive rate, alert volume, and confidence intervals where possible.
6. Compare rule-only, model-only, and hybrid variants.
7. Include inference throughput, memory use, and hardware/software versions.
8. Publish configuration, random seeds, and scripts needed to reproduce the result.

## Important caveats

- Anomaly detection is sensitive to baseline contamination and concept drift.
- A high anomaly score does not prove malicious intent.
- The default thresholds are illustrative and require environment-specific calibration.
- Synthetic patterns can be easier to separate than real attacker behaviour.
- A production deployment must establish an acceptable false-positive budget with operators before enabling automated downstream action.
