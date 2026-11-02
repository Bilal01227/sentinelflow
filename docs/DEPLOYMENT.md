# Deployment: offline batch scorer

This guide packages the current CLI for repeatable offline batch scoring. It does **not** deploy a live network sensor or prevention control.

## Build

```bash
docker build -t sentinelflow:0.2.0 .
```

## Run a scoring job

Mount only the approved input directory. Keep the benign baseline and evaluation file separate.

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --mount type=bind,src="$PWD/input",dst=/input,readonly \
  --mount type=bind,src="$PWD/output",dst=/output \
  sentinelflow:0.2.0 score \
  --input /input/evaluation-flows.csv \
  --baseline /input/benign-baseline.csv \
  --output /output/alerts.csv
```

The image runs as a non-root user. Do not mount Docker sockets, host network namespaces, credentials, or unrelated host directories. Set CPU and memory limits appropriate to the batch size, and protect output files as sensitive security telemetry.

## Production boundary

Before operational use, validate the flow exporter mapping, benchmark against independently labelled traffic, tune thresholds to an agreed false-positive budget, and establish monitoring, retention, access control, incident response, and rollback procedures. The current CLI has no authenticated network API, live ingestion, HA, or automatic response.
