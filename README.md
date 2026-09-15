# FlowWatch

A lightweight, self-hosted network anomaly-detection platform inspired by the operational model of Cisco Secure Network Analytics / Stealthwatch. FlowWatch ingests real NetFlow, scores flows through multiple detection engines, and surfaces prioritized alerts instead of raw traffic noise.

## What It Does

FlowWatch uses three complementary detection lenses:

1. **Traffic-Only**: Isolation Forest over packet, byte, duration, and rate features.
2. **Context-Aware**: Adds device identity, VLAN, role policy, destination familiarity, and port-scan behavior.
3. **Risk-Informed**: Combines anomaly and context signals with asset criticality into a 0-100 score and operational tier.

## Architecture

```text
Router / Switch / Firewall
          │
          │ NetFlow v5 / UDP
          ▼
     FlowWatch Collector
          │
          ├── Traffic Engine
          ├── Context Engine
          └── Risk Engine
                  │
                  ▼
             SQLite Storage
                  │
                  ▼
              Dashboard
```

## Project Structure

```text
backend/
├── app.py
├── collector/
│   └── netflow_v5.py
├── detection/
│   ├── traffic_engine.py
│   ├── context_engine.py
│   └── risk_engine.py
├── inventory.py
├── inventory.json
└── db.py
frontend/
tools/
└── replay_generator.py
requirements.txt
```

## Quick Start

Install dependencies:

```bash
pip install -r requirements.txt
```

Start FlowWatch:

```bash
python3 backend/app.py
```

Open `http://127.0.0.1:5000`.

For a lab without a real exporter, generate NetFlow v5 test traffic:

```bash
python3 tools/replay_generator.py --scenario normal
python3 tools/replay_generator.py --scenario dos
python3 tools/replay_generator.py --scenario portscan
```

## Real NetFlow

The current collector is designed for NetFlow v5 on UDP port `2055` by default. Configure the exporter on an authorized router, switch, firewall, or flow-generating host to send records to the FlowWatch collector.

NetFlow v9 and IPFIX are natural future extensions because they require template handling before record decoding.

## Network Context

`backend/inventory.json` maps IP addresses and subnets to VLANs, roles, names, and criticality. This context is what allows FlowWatch to distinguish unusual traffic from policy violations.

Keep real infrastructure data and credentials out of public repositories.

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Collector and processing status |
| `/api/flows` | GET | Recent scored flows |
| `/api/metrics` | GET | Detection metrics and tier distribution |
| `/api/inventory` | GET | Current network context |
| `/api/inventory/reload` | POST | Reload inventory data |

## Production Considerations

- Run the application behind a production WSGI server.
- Restrict collector and dashboard network access.
- Protect stored flow data because it can reveal sensitive network behavior.
- Consider PostgreSQL or TimescaleDB for high-volume deployments.
- Tune detection baselines against the actual network.

## Security

FlowWatch is defensive monitoring software. Use it only on networks you own or are explicitly authorized to monitor.

## License

MIT

## Author

**Dev Bhargav**

- GitHub: https://github.com/majordevbhargav
- LinkedIn: https://www.linkedin.com/in/devbhargav100
