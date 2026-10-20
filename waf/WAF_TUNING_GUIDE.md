# AgentShield Web Application Firewall (WAF) Tuning & Operations Guide

## Overview

AgentShield employs a defense-in-depth Layer 2 Application Firewall strategy:
1. **Edge Reverse Proxy WAF**: Nginx fronting the system with ModSecurity v3 and the OWASP Core Rule Set (CRS v3.3+).
2. **In-App ASGI WAF Middleware**: Integrated directly inside FastAPI (`backend/app/firewall/app_firewall.py`), providing runtime sliding-window rate limiting, payload size enforcement, CRS-aligned attack signature inspection, credential redaction, and strict security header injection.

---

## 1. Operating Modes: Detection-Only vs. Blocking

The WAF supports two primary operational modes:

| Mode | Behavior | Use Case |
|---|---|---|
| **`DETECTION_ONLY`** (Default) | Inspects requests, logs security events and rule matches, but **never drops legitimate traffic**. Returns HTTP 200/normal status. | Initial deployment, baseline calibration, and testing against production workloads. |
| **`BLOCKING`** | Evaluates attack signatures, payload sizes, and rate limits. If a violation occurs, the request is terminated immediately with **HTTP 403 Forbidden** or **HTTP 429 Too Many Requests**. | Hardened production operation after false positives are eliminated. |

### How to Toggle Modes in ASGI Application WAF
Use the authenticated AgentShield API or dashboard:
```http
POST /api/firewall/waf/mode
Content-Type: application/json
Authorization: Bearer <TOKEN>

{
  "mode": "BLOCKING"
}
```
*(Options: `DETECTION_ONLY`, `BLOCKING`)*

### How to Toggle Modes in Nginx ModSecurity
In `/etc/nginx/modsec/modsecurity.conf`:
- **Detection Only**:
  ```nginx
  SecRuleEngine DetectionOnly
  ```
- **Active Blocking**:
  ```nginx
  SecRuleEngine On
  ```
Reload Nginx gracefully without downtime:
```bash
nginx -t && nginx -s reload
```

---

## 2. Tuning False Positives

When legitimate user traffic matches strict CRS rules, use targeted exclusions instead of disabling entire security categories.

### Common False Positives in AgentShield
1. **Network Scan Subnet Lists**:
   - `942100` (SQL Injection) may trigger when administrators enter CIDR strings like `192.168.1.0/24` or commas in target lists.
   - **Tuning**: In `waf/nginx_modsecurity/rules/agentshield_tuning.conf`, rule `100010` excludes ARGS:target_subnets from rule `942100`.
2. **LLM Prompts & Security Policy Queries**:
   - Security prompts often discuss exploits, SQL keywords (`SELECT * FROM users`), or Linux bash commands.
   - **Tuning**: Rule `100020` excludes the prompt fields on `/api/jarvis` and `/api/agent` from generic SQLi/RCE inspection. *Note: Layer 3 AI Agent Security Firewall takes over deep semantic verification of tool calls and prompt injection defense.*

---

## 3. Anomaly Scoring Thresholds

ModSecurity uses collaborative anomaly scoring. Instead of blocking on the first rule hit, scores accumulate:
- In `crs-setup.conf`:
  - `tx.inbound_anomaly_score_threshold=5` (Standard production threshold)
  - During initial tuning in staging, increase to `10` or `15` to capture low-confidence triggers without false-positive lockouts.

---

## 4. Rate Limiting Policy

- **General API Routes** (`/api/*`): 60 requests per minute per IP, with a burst buffer of 15.
- **Authentication Endpoints** (`/api/auth/*`): 10 requests per minute per IP, with a burst buffer of 5.
- **Exceeded Limit Response**: HTTP 429 Too Many Requests with `Retry-After: <seconds>` header.

---

## 5. Emergency Rollback & Bypass Procedures

### Procedure A: Emergency Bypass of In-App WAF
If a critical production workflow is inadvertently blocked:
1. Call the emergency WAF mode switch to switch to `DETECTION_ONLY`:
   ```bash
   curl -X POST http://localhost:8000/api/firewall/waf/mode \
     -H "Content-Type: application/json" \
     -d '{"mode": "DETECTION_ONLY"}'
   ```

### Procedure B: Emergency Bypass of Nginx ModSecurity
If ModSecurity proxy needs to be temporarily deactivated:
1. Edit `/etc/nginx/nginx.conf`:
   ```nginx
   # Change modsecurity on; to:
   modsecurity off;
   ```
2. Reload Nginx:
   ```bash
   nginx -s reload
   ```

---

## 6. Updating Rulesets
1. Periodically fetch official OWASP CRS updates:
   ```bash
   cd /etc/nginx/modsec/coreruleset
   git pull origin main
   ```
2. Test configuration syntax before reloading:
   ```bash
   nginx -t
   ```
3. Verify test traffic using AgentShield test suite:
   ```bash
   pytest backend/tests/test_three_layer_firewall.py -k "test_waf"
   ```
