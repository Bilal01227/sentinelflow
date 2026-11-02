# Security policy

## Scope

SentinelFlow 0.2.x processes offline, normalized network-flow summaries. It does not capture traffic, execute payloads, exploit hosts, modify firewall rules, or automatically block connections.

## Reporting a vulnerability

Please do not publish sensitive exploit details in a public issue. Use GitHub's private vulnerability reporting feature for this repository where available. Include affected version/commit, impact, reproduction steps, and a proposed mitigation. Do not include real customer traffic, private IP inventories, or secrets.

## Operational security

- Run with least privilege and isolate the process and input files.
- Do not ingest data you are not authorized to process.
- Treat flow records and generated alert files as sensitive operational data.
- Do not load untrusted serialized estimator artifacts. This release does not implement external model deserialization.
- Keep dependencies patched and review automated dependency-audit findings.

## Supported versions

Only the latest release is supported while the project is in alpha.
