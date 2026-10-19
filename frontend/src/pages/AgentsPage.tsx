import React, { useState } from "react";
import { Bot, Plus, Search, Power, Shield, Lock, Eye, AlertCircle, X, ArrowRight } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
  onRefresh: () => void;
  onKillAgent: (agent: Agent) => void;
  onReactivateAgent: (agent: Agent) => void;
}

export const AgentsPage: React.FC<Props> = ({
  agents,
  onRefresh,
  onKillAgent,
  onReactivateAgent
}) => {
  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [agentForm, setAgentForm] = useState({
    name: "",
    owner: "Security Ops",
    model: "GPT-4o Enterprise",
    purpose: "",
    tools: "tool-db, tool-files"
  });
  const [busy, setBusy] = useState(false);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await request("/api/agents", {
        method: "POST",
        body: JSON.stringify({
          ...agentForm,
          tools: agentForm.tools.split(",").map(t => t.trim()).filter(Boolean)
        })
      });
      setShowCreate(false);
      setAgentForm({ name: "", owner: "Security Ops", model: "GPT-4o Enterprise", purpose: "", tools: "tool-db, tool-files" });
      onRefresh();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to register agent");
    } finally {
      setBusy(false);
    }
  }

  const filtered = agents.filter(a =>
    `${a.name} ${a.id} ${a.owner} ${a.purpose}`.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">IDENTITY & ACCESS MANAGEMENT</div>
          <h1>AI Agent Inventory & Lifecycle</h1>
          <p>Register, inspect permissions, review behavioral posture, and enforce emergency containment across all AI agents.</p>
        </div>
        <button className="primary-button" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> Register Agent
        </button>
      </div>

      {showCreate && (
        <section className="panel form-panel">
          <div className="panel-heading">
            <div>
              <h2>Register Autonomous AI Agent</h2>
              <p>Establish unique identity, purpose, and initial least-privilege tool boundary.</p>
            </div>
            <button className="icon-button" onClick={() => setShowCreate(false)}>
              <X size={16} />
            </button>
          </div>
          <form onSubmit={handleCreate} className="form-grid">
            <label>
              Agent Name
              <input required value={agentForm.name} onChange={e => setAgentForm({ ...agentForm, name: e.target.value })} placeholder="e.g. FinanceAnalyzer-02" />
            </label>
            <label>
              Owner / Organization
              <input value={agentForm.owner} onChange={e => setAgentForm({ ...agentForm, owner: e.target.value })} />
            </label>
            <label>
              Model Specification
              <input value={agentForm.model} onChange={e => setAgentForm({ ...agentForm, model: e.target.value })} />
            </label>
            <label>
              Declared Purpose
              <input required value={agentForm.purpose} onChange={e => setAgentForm({ ...agentForm, purpose: e.target.value })} placeholder="State specific business domain of agent" />
            </label>
            <label className="wide">
              Connected Tools (comma-separated IDs)
              <input value={agentForm.tools} onChange={e => setAgentForm({ ...agentForm, tools: e.target.value })} />
            </label>
            <div className="wide form-actions">
              <button type="submit" className="primary-button" disabled={busy}>
                <Plus size={15} /> Confirm Registration
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Registered Agents ({filtered.length})</h2>
            <p>Active control plane participants</p>
          </div>
          <div className="search-box">
            <Search size={15} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search agent name, ID..." />
          </div>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>AGENT IDENTITY</th>
                <th>MODEL</th>
                <th>OWNER</th>
                <th>STATUS</th>
                <th>RISK SCORE</th>
                <th>TRUST SCORE</th>
                <th>CONNECTED TOOLS</th>
                <th>CONTROLS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id}>
                  <td>
                    <div className="agent-cell clickable" onClick={() => setSelectedAgent(a)}>
                      <div className="agent-icon"><Bot size={17} /></div>
                      <div>
                        <strong>{a.name}</strong>
                        <div className="subtext">{a.id}</div>
                      </div>
                    </div>
                  </td>
                  <td><span className="code-tag">{a.model}</span></td>
                  <td>{a.owner}</td>
                  <td><span className={`badge ${a.status.toLowerCase()}`}>{a.status}</span></td>
                  <td>
                    <div className="risk-wrap">
                      <div className="risk-track">
                        <div className={`risk-fill ${a.risk_score >= 70 ? "danger" : a.risk_score >= 40 ? "warning" : "safe"}`} style={{ width: `${a.risk_score}%` }} />
                      </div>
                      <span>{a.risk_score}</span>
                    </div>
                  </td>
                  <td><span className="trust-indicator">{a.trust_score ?? 90}%</span></td>
                  <td>
                    <div className="tool-tags">
                      {(a.tools || []).map(t => <span key={t}>{t}</span>)}
                    </div>
                  </td>
                  <td>
                    <div className="inline-actions">
                      <button className="secondary-button small-btn" onClick={() => setSelectedAgent(a)}>Inspect</button>
                      {a.status === "ACTIVE" ? (
                        <button className="kill-button" onClick={() => onKillAgent(a)}>
                          <Power size={13} /> Kill
                        </button>
                      ) : (
                        <button className="approve-button" onClick={() => onReactivateAgent(a)}>
                          Reactivate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Agent Detail Drawer / Modal */}
      {selectedAgent && (
        <div className="modal-backdrop" onClick={() => setSelectedAgent(null)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="agent-cell">
                <div className="agent-icon"><Bot size={22}/></div>
                <div>
                  <h2>{selectedAgent.name}</h2>
                  <small className="subtext">{selectedAgent.id} · {selectedAgent.model}</small>
                </div>
              </div>
              <button className="icon-button" onClick={() => setSelectedAgent(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body">
              <div className="stat-row">
                <div className="stat-pill">Status: <strong>{selectedAgent.status}</strong></div>
                <div className="stat-pill">Risk Score: <strong>{selectedAgent.risk_score}/100</strong></div>
                <div className="stat-pill">Trust Score: <strong>{selectedAgent.trust_score ?? 90}/100</strong></div>
              </div>

              <h3>Declared Purpose & System Prompt</h3>
              <p className="purpose-box">{selectedAgent.purpose}</p>

              <h3>Baseline System Instructions</h3>
              <div className="code-block-preview">
                {selectedAgent.baseline_instructions || "Strict Zero-Trust policy boundaries enforced."}
              </div>

              <h3>Fine-Grained Permissions</h3>
              <div className="permissions-grid">
                {Object.entries(selectedAgent.permissions || {}).map(([action, resources]) => (
                  <div key={action} className="perm-card">
                    <span className="perm-action">{action.toUpperCase()}</span>
                    <div className="perm-resources">
                      {resources.length > 0 ? (
                        resources.map(r => <span key={r} className="perm-tag">{r}</span>)
                      ) : (
                        <span className="muted-italic">No permissions granted (Denied)</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="modal-footer-actions">
                {selectedAgent.status === "ACTIVE" ? (
                  <button className="kill-button full-button" onClick={() => { onKillAgent(selectedAgent); setSelectedAgent(null); }}>
                    <Power size={15} /> Emergency Kill Switch
                  </button>
                ) : (
                  <button className="approve-button full-button" onClick={() => { onReactivateAgent(selectedAgent); setSelectedAgent(null); }}>
                    Reactivate Agent
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
