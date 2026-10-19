import React, { useState } from "react";
import { Radio, Send, ShieldAlert, CheckCircle2, XCircle, Clock3, AlertCircle, Sparkles, Activity } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
  onRefresh: () => void;
}

export const AgentLabPage: React.FC<Props> = ({ agents, onRefresh }) => {
  const [lab, setLab] = useState({
    agent_id: agents.find(a => a.status === "ACTIVE")?.id || "",
    action: "READ",
    target: "internal:database",
    payload: "",
    declared_intent: "Generate financial summary report"
  });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);

  async function handleEvaluate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await request<any>("/api/actions/evaluate", {
        method: "POST",
        body: JSON.stringify(lab)
      });
      setResult(res);
      onRefresh();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Evaluation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">ZERO-TRUST SECURITY LAB</div>
          <h1>Agent Action Evaluation Laboratory</h1>
          <p>Submit synthetic or instrumented tool invocations to evaluate prompt injection, DLP exposure, fine-grained permissions, and explainable risk scores.</p>
        </div>
      </div>

      <div className="lab-layout">
        {/* Input Form Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Action Invocation Parameters</h2>
              <p>Simulate action execution at the policy boundary</p>
            </div>
          </div>
          <form onSubmit={handleEvaluate} className="stack-form">
            <label>
              Target AI Agent
              <select
                required
                value={lab.agent_id}
                onChange={e => setLab({ ...lab, agent_id: e.target.value })}
              >
                {agents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.status}) — Risk {a.risk_score}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Requested Tool Action
              <select
                value={lab.action}
                onChange={e => setLab({ ...lab, action: e.target.value })}
              >
                {["READ", "ANALYZE", "WRITE", "SEND", "EXPORT", "DELETE", "EXECUTE", "TRANSFER"].map(a => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
            </label>

            <label>
              Target Resource / Egress Destination
              <input
                required
                value={lab.target}
                onChange={e => setLab({ ...lab, target: e.target.value })}
                placeholder="e.g. database:finance_records or https://external-api.com"
              />
            </label>

            <label>
              Declared Task Intent
              <input
                value={lab.declared_intent}
                onChange={e => setLab({ ...lab, declared_intent: e.target.value })}
                placeholder="Declare high-level agent objective for intent-aware policy validation"
              />
            </label>

            <label>
              Payload / Prompt Content
              <textarea
                rows={5}
                value={lab.payload}
                onChange={e => setLab({ ...lab, payload: e.target.value })}
                placeholder="Input prompt, retrieved document, or outbound tool parameters to inspect for injection and DLP secrets..."
              />
            </label>

            <button type="submit" className="primary-button full-button" disabled={busy || !lab.agent_id}>
              <Send size={15} /> Evaluate Against Zero-Trust Gateway
            </button>
          </form>
        </section>

        {/* Results Panel */}
        <section className="panel result-panel">
          <div className="panel-heading">
            <div>
              <h2>Gateway Decision & Explainable Analytics</h2>
              <p>Multimodal inspector, Zero-Trust policy engine, and ML scoring</p>
            </div>
          </div>

          {!result ? (
            <div className="empty-state">
              <div className="empty-icon"><Activity size={26} /></div>
              <strong>Awaiting Action Evaluation</strong>
              <p>Submit a simulated tool call on the left to inspect the policy decision, explainable reasoning chain, and risk score.</p>
            </div>
          ) : (
            <div className="result-body">
              <div className={`decision-card ${result.decision.toLowerCase()}`}>
                <div className="decision-header">
                  <span>ZERO-TRUST POLICY DECISION</span>
                  <strong>{result.decision.replace("_", " ")}</strong>
                </div>
                <div className="decision-meta">
                  <span>Dynamic Risk Score: <strong>{result.risk_score}/100</strong></span>
                  <span>Continuous Trust: <strong>{result.trust_score}/100</strong></span>
                </div>
              </div>

              <h3>Contributing Decision Signals</h3>
              <div className="reasons-list">
                {result.reasons.map((r: string, idx: number) => (
                  <div key={idx} className="reason-row">
                    <ShieldAlert size={15} />
                    <span>{r}</span>
                  </div>
                ))}
              </div>

              <h3>Security Inspection Findings</h3>
              <div className="signal-grid">
                <div className={`signal ${result.prompt_injection?.is_injection ? "signal-active" : "signal-clear"}`}>
                  <span>Prompt Injection</span>
                  <strong>{result.prompt_injection?.is_injection ? "DETECTED" : "CLEAN"}</strong>
                </div>
                <div className={`signal ${result.dlp?.has_sensitive_data ? "signal-active" : "signal-clear"}`}>
                  <span>DLP Sensitive Patterns</span>
                  <strong>{result.dlp?.has_sensitive_data ? "EXPOSURE" : "CLEAN"}</strong>
                </div>
              </div>

              {result.dlp?.violations?.length > 0 && (
                <div className="dlp-violations-box">
                  <strong>DLP Policy Matches:</strong>
                  <ul>
                    {result.dlp.violations.map((v: any, i: number) => (
                      <li key={i}>{v.description} ({v.severity})</li>
                    ))}
                  </ul>
                  <small className="muted">Sanitized output: {result.dlp.sanitized_preview}</small>
                </div>
              )}

              {result.analyst_report && (
                <div className="analyst-report-box">
                  <div className="report-title">
                    <Sparkles size={16} /> Explainable AI Security Analyst Report
                  </div>
                  <p>{result.analyst_report.summary}</p>
                  <strong>Defensive Recommendations:</strong>
                  <ul>
                    {result.analyst_report.recommended_defensive_actions.map((rec: string, i: number) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
