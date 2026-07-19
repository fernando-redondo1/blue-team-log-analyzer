# Log Anomaly Detector

A Go-based security analytics prototype for detecting suspicious activity in authentication and web access logs. The project is designed as a practical Blue Team/SOC-oriented portfolio piece that demonstrates how log ingestion, feature engineering, and alert generation can support defensive operations.

## Why this project matters

This tool fits into a defensive architecture as a lightweight detection layer that can complement a collector and a SIEM:

- collector: ingests and forwards logs
- SIEM: centralizes and correlates alerts
- detection layer: identifies suspicious patterns such as brute-force attempts, repeated failures, or abnormal access behavior

## What it does

- parses SSH authentication logs such as auth.log
- parses common Apache access logs
- normalizes events into a simple internal model
- builds per-IP behavioral features
- generates alerts for suspicious activity
- optionally writes alerts to JSON for downstream integration

## Project structure

- cmd/log-anomaly-detector: CLI entry point
- internal/parser: log parsing for SSH and Apache formats
- internal/features: construction of behavioral features
- internal/detection: scoring and alert generation
- internal/report: console and JSON reporting
- testdata: sample logs for testing and demos

## Usage

### SSH logs

```bash
go run ./cmd/log-anomaly-detector -type ssh ./testdata/sample-auth.log
```

### Apache logs

```bash
go run ./cmd/log-anomaly-detector -type apache ./testdata/sample-apache.log
```

### JSON output

```bash
go run ./cmd/log-anomaly-detector -type ssh -json ./out/alerts.json ./testdata/sample-auth.log
```

## Development

```bash
go test ./...
```

## Roadmap

- add richer anomaly scoring and explainability
- support more log sources and parsers
- improve rule tuning for real-world false-positive control
- evolve toward a more advanced ML-based detection layer
