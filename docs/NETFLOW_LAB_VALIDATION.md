# NetFlow Lab Validation Checklist

Use this checklist to validate FlowWatch in a controlled lab before relying on its alerts. It focuses on repeatable checks rather than treating a running dashboard as proof that detection works.

## 1. Prepare a clean test

- [ ] Install dependencies from `requirements.txt` in an isolated Python environment.
- [ ] Start the application with `python3 backend/app.py`.
- [ ] Open `http://127.0.0.1:5000` and confirm the application responds.
- [ ] Check `GET /api/status` and record the collector and processing status.
- [ ] Check `GET /api/metrics` and `GET /api/flows` before replaying traffic. Save this as the baseline.
- [ ] Use synthetic replay data or telemetry from infrastructure you own or are authorized to monitor.

## 2. Replay scenarios one at a time

Run each scenario separately so results can be attributed to a known input:

```bash
python3 tools/replay_generator.py --scenario normal
python3 tools/replay_generator.py --scenario dos
python3 tools/replay_generator.py --scenario portscan
```

After each run, inspect `/api/flows`, `/api/metrics`, and the dashboard. Allow for the collector's configured processing interval before deciding that an event was missed.

| Scenario | What to verify | Important caveat |
| --- | --- | --- |
| `normal` | Flows are received and represented without an unexpected flood of high-risk findings. | A normal scenario is a baseline sample, not proof that all benign traffic is classified correctly. |
| `dos` | High-volume or rate-related features change and the detector produces explainable findings when the scenario crosses its configured thresholds. | Do not assume every high-volume flow is malicious; legitimate bursts can look similar. |
| `portscan` | Repeated destination-port or connection patterns are visible and findings include enough context to investigate. | Scanning patterns can also occur during authorized inventory and testing. |

## 3. Validate context enrichment

- [ ] Confirm a known test device maps to the expected inventory entry.
- [ ] Check that VLAN or network-role fields are populated when the inventory provides them.
- [ ] Verify destination familiarity and asset criticality only affect scoring when the relevant context exists.
- [ ] Test an unknown device or destination and confirm missing context is handled safely rather than crashing processing.
- [ ] Reload inventory through `POST /api/inventory/reload`, then verify the updated context through `GET /api/inventory`.

Do not put production IP inventories, credentials, or sensitive topology details into public test fixtures.

## 4. Record results

For each run, record:

| Field | Record |
| --- | --- |
| Date and code revision | When the test ran and the commit SHA |
| Scenario | `normal`, `dos`, or `portscan` |
| Input | Synthetic replay or authorized lab source |
| Ingestion | Whether new flows appeared |
| Detection | Finding count and representative risk scores |
| Context | Which identity, role, or asset fields were available |
| Errors | Relevant logs, exceptions, or API failures |
| Outcome | Pass, fail, or needs investigation, with a short reason |

Use the same scenario inputs and configuration when comparing changes. Avoid claiming precision, recall, or false-positive rates unless the test has labelled ground truth and those metrics have actually been calculated.

## 5. Troubleshooting guide

### The dashboard opens, but no flows appear

1. Check `GET /api/status` for collector state.
2. Confirm the replay generator completed and inspect application logs.
3. Verify the configured listener, protocol, and port match the telemetry sender.
4. Check host firewall rules and network reachability in the lab.
5. Confirm that the sender's NetFlow version is supported by the current collector.

### Flows appear, but alerts do not

1. Confirm the replay scenario produced the expected traffic features.
2. Inspect the scored flow data and configured detection thresholds.
3. Check whether context fields are absent or mapped differently than expected.
4. Repeat the scenario from a clean baseline and compare results before changing thresholds.

### Context appears stale

1. Validate the inventory file format and required fields.
2. Call `POST /api/inventory/reload` and check the response.
3. Query `GET /api/inventory` to confirm the current data.
4. Review logs for parsing errors and malformed entries.

## Acceptance criteria

A lab run is ready for review when telemetry ingestion is observable, each replay scenario has a recorded outcome, findings can be traced to the input and relevant features, missing context does not crash processing, and any limitations are documented. This checklist is a manual validation aid, not an automated test suite or a guarantee of production readiness.
