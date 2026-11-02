# Sensor telemetry ingestion

SentinelFlow supports offline JSON Lines ingestion from Zeek connection logs
and Suricata EVE flow events.

## Zeek

Export conn.log as JSON, then run:

    sentinelflow ingest --source zeek --input conn.log --output artifacts/zeek-flows.csv
    sentinelflow score --input artifacts/zeek-flows.csv --baseline benign-baseline.csv

The adapter maps ts, id.orig_h, id.resp_h, proto, duration, orig_bytes,
resp_bytes, packet counts, and conn_state. Zeek log schemas vary with loaded
scripts and local configuration; verify source fields against your sensor.

## Suricata

Provide EVE JSONL containing flow events:

    sentinelflow ingest --source suricata --input eve.json --output artifacts/suricata-flows.csv
    sentinelflow score --input artifacts/suricata-flows.csv --baseline benign-baseline.csv

The adapter maps flow age, directional bytes, and packet counts. Alert, DNS,
and HTTP events are skipped by this flow adapter rather than mislabeled.

## Semantics and limitations

- Offline file processing only: no live tailer, packet sensor, broker consumer,
  PCAP parser, or streaming pipeline.
- Each source record becomes one flow row; this is not multi-flow aggregation.
- Source/destination ports, sensor IDs, VLANs, interfaces, and source event IDs
  are not retained by the current canonical schema.
- unique_dst_ports and same_dst_port_ratio are placeholders for one observed
  flow, not host-level scan statistics.
- Zeek connection states are conservative proxies for failure/SYN/RST signals.
  Suricata flow state is not a packet-level TCP flag history, so SYN evidence
  is not inferred from it.
- Validate exporter versions, timestamps, counters, and local field semantics
  before trusting model scores.

## Official format references

- Zeek JSON logs: https://docs.zeek.org/en/master/tutorial/logs.html
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
