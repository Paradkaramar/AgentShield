# AgentShield — Continuous Network Monitoring & Asset Discovery Specification

## 1. Executive Summary & Zero-Trust Mandate
Continuous Network Monitoring is an essential defense-in-depth subsystem of AgentShield. As autonomous AI agents interact with infrastructure, tools, and execution environments, the platform continuously monitors the network attack surface while adhering to a strict Zero-Trust model:
- **Authorized Scope Confinement**: Probes are restricted exclusively to administrator-configured, pre-approved IP ranges (CIDRs) and enclaves. Arbitrary public IP ranges or unapproved targets are blocked at the engine gate.
- **Fact vs. Threat Separation**: Sensor observations strictly partition verified empirical probe data (e.g. "TCP port 6379 responded with banner '+PONG' in 11.2ms") from suspected threat vectors (e.g. "Unauthenticated Redis in-memory cache exposure permitting state manipulation").
- **Reliability & Safety Interlocks**: Scanners use non-disruptive TCP connect checks, strict timeouts, rate limiting, duplicate scan prevention via state locks, and an instant global emergency stop.

---

## 2. Core Architecture

```
                                  +---------------------------------------+
                                  |     Administrator / SecOps UI        |
                                  |    (Network Monitoring Dashboard)     |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +-------------------+-------------------+
                                  |     JARVIS Multilingual Assistant     |
                                  |    (EN, Hindi, Marathi, Hinglish)     |
                                  +-------------------+-------------------+
                                                      |
                                      Authenticated REST API (/api/network/*)
                                                      |
                                                      v
+---------------------------------------------------------------------------------------------------+
| AgentShield Network Monitoring Subsystem                                                          |
|                                                                                                   |
|  +-----------------------------+      +---------------------------+      +---------------------+  |
|  | Approved Scope Guard        |      | Background Scheduler      |      | Emergency Stop      |  |
|  | - Strict CIDR Confinement   | ---> | - Configurable Interval   | <--- | - Instant Job Abort |  |
|  | - IP Exclusion Filter       |      | - Lock & Overlap Check    |      | - Audit Entry Log   |  |
|  +-----------------------------+      +-------------+-------------+      +---------------------+  |
|                                                     |                                             |
|                                                     v                                             |
|                                       +-------------+-------------+                               |
|                                       | Non-Disruptive Safe Probe |                               |
|                                       | - asyncio Concurrency     |                               |
|                                       | - Safe TCP Handshake Peek |                               |
|                                       | - Strict Latency Watchdog |                               |
|                                       +-------------+-------------+                               |
|                                                     |                                             |
|                                                     v                                             |
|                                       +-------------+-------------+                               |
|                                       | Baseline Comparison Diff  |                               |
|                                       | - New Host Detection      |                               |
|                                       | - Unexpected Open Port    |                               |
|                                       | - Service Banner Changes  |                               |
|                                       +-------------+-------------+                               |
|                                                     |                                             |
|                                                     v                                             |
|                                       +-------------+-------------+                               |
|                                       | Fact / Threat Partition   |                               |
|                                       | - Verified Empirical Fact |                               |
|                                       | - Hypothesized Risk       |                               |
|                                       +---------------------------+                               |
+---------------------------------------------------------------------------------------------------+
                                                      |
                                                      v
                                   +------------------+-------------------+
                                   |    Persistence & Audit Ledger        |
                                   |    (SQLite & PostgreSQL 13+)         |
                                   +--------------------------------------+
```

---

## 3. Scope Confinement & Safety Rules

1. **Explicit Scope Required**: Scanning cannot initiate if `approved_scan_scopes` contains no active CIDRs.
2. **Exclusion Precedence**: If an IP falls inside an approved CIDR (e.g., `192.168.1.1` in `192.168.1.0/24`) but is listed in `network_exclusions`, it is skipped prior to any socket creation.
3. **No Public IP Scans**: Administrator APIs validate CIDR inputs using Python's `ipaddress` library and reject public non-private/non-loopback ranges unless special enclaves are granted.
4. **Duplicate Scan Prevention**: The engine uses an `asyncio.Lock()` and atomic database job state verification. If a sweep is running, overlapping requests are rejected with a `SKIPPED` status.
5. **Duration Limits & Watchdogs**: Each scan sweep runs under `scan_duration_limit_seconds` (default: 120s). If exceeded, in-flight probes terminate cleanly and the job is marked `FAILED` without crashing the daemon.
6. **Emergency Stop**: The `/api/network/controls/emergency-stop` endpoint or JARVIS command activates a global safety kill switch that cancels running tasks and locks down future sweeps until an explicit reset.

---

## 4. Telemetry Schema & Persistence

AgentShield supports seamless operation on both SQLite (local development and offline enclaves) and PostgreSQL (enterprise production).

### Schema Tables:
1. `approved_scan_scopes`: Configured IPv4 CIDR blocks and asset tags.
2. `network_exclusions`: Specific IPs excluded from scanning (e.g. gateway routers, medical/OT devices).
3. `network_monitoring_config`: Singleton configuration holding state, intervals, timeouts, and port lists.
4. `scan_jobs`: Execution ledger tracking duration, status, hosts found, and errors.
5. `network_assets`: Inventory of reachable and offline nodes, tracking baseline approval.
6. `service_observations`: Port-level empirical observations (ports, protocols, service names, banners).
7. `network_security_alerts`: Deviations from baseline with distinct `observed_fact` and `suspected_threat` fields.

*For PostgreSQL deployments, run `backend/app/db/postgres_schema.sql`.*

---

## 5. JARVIS Multilingual Voice & Chat Integration

JARVIS operates as an authenticated security officer assistant defending the platform. JARVIS translates natural-language commands in English, Hindi, Marathi, and Hinglish directly into authorized tool calls.

| Natural Language Command | Language | Tool Invoked |
|---|---|---|
| "Jarvis, network monitoring status batao." | Hinglish / Hindi | `get_network_monitoring_status` |
| "Show newly discovered devices." | English | `get_network_discovered_devices` |
| "Mala suspicious network activity dakhav." | Marathi | `get_network_security_alerts` |
| "Start monitoring my approved network." | English | `start_network_monitoring` |
| "Stop the current monitoring job." | English | `stop_network_monitoring` |
| "Approved network monitoring shuru karo" | Hindi | `start_network_monitoring` |
| "Sadhya chaloo asleli monitoring thambva" | Marathi | `stop_network_monitoring` |
| "Navin shodhlele devices dakhav" | Marathi | `get_network_discovered_devices` |

**Security Guardrail**: JARVIS will NEVER expand scan scopes through natural-language prompts. If a user asks to scan arbitrary external IPs (e.g. "Scan 8.8.8.8"), the tool verifies approved CIDRs and rejects the command with a Scope Violation warning.

---

## 6. Verification & Automated Tests

The automated test suite (`backend/tests/test_network_monitoring.py`) tests:
1. **Scope validation**: CIDR matching, rejection of public IPs, exclusion filtering.
2. **RBAC & Authorization**: Admin rights required for scope changes, analyst rights for alert triage.
3. **Duplicate Prevention**: Rejection of concurrent sweeps.
4. **Emergency Stop Lifecycle**: Immediate abort, lock engagement, and audit logging.
5. **Baseline Comparison**: Fact vs. threat separation on unexpected open ports and rogue hosts.
6. **JARVIS Multilingual Commands**: Verification of parsing across English, Hindi, Marathi, and Hinglish.

Run all tests via:
```bash
python -m pytest backend/tests
```
