# FlowWatch

A lightweight, self-hosted network observability and anomaly-detection platform built around NetFlow.

FlowWatch explores how raw network telemetry can be enriched with **device context, network roles, and asset risk** to produce more useful security signals.

## Why I Built It

While learning about Cisco Secure Network Analytics / Stealthwatch, I wanted to understand the engineering ideas behind turning network flows into prioritized security information.

FlowWatch is my practical exploration of that problem.

## Detection Model

| Engine | What it uses | Purpose |
|---|---|---|
| Traffic-Only | Packets, bytes, duration, rate | Find unusual traffic behaviour |
| Context-Aware | Traffic + device/network context | Identify policy and behavioural anomalies |
| Risk-Informed | Traffic + context + asset criticality | Prioritize findings with a 0-100 risk score |

## Architecture

```text
Router / Switch / Firewall
          |
          | NetFlow v5
          v
     FlowWatch Collector
          |
     +----+----+
     |    |    |
 Traffic Context Risk
     |    |    |
     +----+----+
          |
          v
       Storage
          |
          v
      Dashboard
```

## Current Capabilities

- NetFlow v5 collection
- Traffic anomaly detection
- Network-context enrichment
- Asset criticality and risk scoring
- Flow inspection
- Inventory-based context
- Dashboard and REST API
- Replay tooling for controlled lab testing

## Quick Start

```bash
pip install -r requirements.txt
python3 backend/app.py
```

Open:

```text
http://127.0.0.1:5000
```

For lab testing:

```bash
python3 tools/replay_generator.py --scenario normal
python3 tools/replay_generator.py --scenario dos
python3 tools/replay_generator.py --scenario portscan
```

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Collector and processing status |
| `/api/flows` | GET | Recent scored flows |
| `/api/metrics` | GET | Detection metrics |
| `/api/inventory` | GET | Network context |
| `/api/inventory/reload` | POST | Reload inventory |

## What I Am Learning

This project connects networking with software engineering and security:

- NetFlow and network telemetry
- Anomaly detection
- Python backend development
- Security analytics
- Risk modelling
- Network context enrichment
- Defensive monitoring

## Next Steps

- NetFlow v9 / IPFIX
- Better baseline learning
- PostgreSQL / TimescaleDB
- Alerting
- More Cisco integrations
- Detection evaluation with real lab baselines

## Security

Use FlowWatch only on networks you own or are explicitly authorized to monitor. Keep real infrastructure data and credentials out of the repository.

## Author

**Dev Bhargav**

[GitHub](https://github.com/majordevbhargav) · [LinkedIn](https://www.linkedin.com/in/devbhargav100)
