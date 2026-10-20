# AgentShield — Security Architecture Specification

Tagline: **"Who Controls the AI?"**

## 1. Architectural Principles

1. **Default-Deny Zero-Trust Posture**: All state-altering and egress operations (`WRITE`, `DELETE`, `EXPORT`, `SEND`, `EXECUTE`, `TRANSFER`) require explicit fine-grained permission authorization. If no explicit grant exists, the operation fails closed.
2. **Severed Enforcement Boundary**: The agent never communicates directly with raw databases, external webhooks, or cloud services. All tool invocations must route through the Policy Enforcement Gateway and Secret-Aware Tool Proxy.
3. **Defense-in-Depth Inspection**: Every invocation undergoes independent multi-layer inspection:
   - Rule-based + semantic prompt injection heuristics
   - Data Loss Prevention (PII & credentials)
   - Canary honeytoken tripwires
   - Defensive reverse-engineering probing detection
   - Intent-aware policy consistency checks
4. **Cryptographic Non-Repudiation**: Every security decision, policy update, and approval is recorded in an append-only SHA-256 chained audit ledger (`prev_hash` $\rightarrow$ `current_hash`).
5. **Explainability Over Obscurity**: Every block, approval, or risk penalty is accompanied by an explainable factor breakdown and counterfactual analysis.

---

## 2. Threat Model & Mitigations

| Threat | Attack Vector | AgentShield Mitigation Engine |
|---|---|---|
| **Direct Prompt Injection** (OWASP LLM01) | Adversary supplies override instructions (e.g. `ignore previous instructions`) | `engines/prompt_injection.py` with 18 heuristic signatures, Unicode normalization, and Base64 unpacking |
| **Data Exfiltration** (OWASP LLM02) | Coerced egress of PII or credentials to pastebins or dropzones | `engines/dlp.py` with automatic masking & `engines/policy_engine.py` blocking unlisted egress |
| **Privilege Escalation** (OWASP LLM08) | Agent attempting unpermitted destructive tools (`DELETE`, `DROP TABLE`) | `engines/policy_engine.py` fine-grained permission matrix enforcement & mandatory Human Approval |
| **Compromised Canary Access** | Agent accessing synthetic canary tokens in memory or mock tables | `engines/canary.py` instant tripwire trigger & automatic critical incident creation |
| **Multi-Agent Privilege Jump** | Low-privilege agent delegating to high-privilege agent | `engines/multi_agent.py` cross-agent delegation verification with 15% trust decay per hop |
| **Rogue / Shadow AI** | Uninstrumented process calling external LLM APIs directly | `engines/shadow_ai.py` network egress inspection & onboarding workflow |
| **Network Attack Surface Drift** | Newly spawned rogue nodes, unexpected open ports, service changes in agent enclaves | `engines/network_scanner.py` & `services/network_monitor.py` continuous authorized sweeps & baseline diff |
| **Control Plane Probing** | Agent inspecting prompt templates or internal security source code | `engines/reverse_engineering.py` defensive reverse engineering detection |

---

## 3. Cryptographic Audit Ledger Specification

Each audit entry $E_i$ is bound to the preceding entry $E_{i-1}$ via:
$$H_i = \text{SHA-256}(H_{i-1} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{details\_json})$$
Where $H_0$ is the 64-character Genesis Hash `0000000000000000000000000000000000000000000000000000000000000000`.
Any retroactive modification of $E_k$ breaks all hashes $H_j$ for $j \ge k$, instantly flagged by `/api/audit/verify`.
