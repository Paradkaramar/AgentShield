import React from "react";
import {
  Bot, Activity, ShieldAlert, Clock3, AlertTriangle, Crosshair,
  ArrowUpRight, Plus, RefreshCw, CheckCircle2, XCircle
} from "lucide-react";
import { SOC_Overview, Agent, EventItem } from "../types";
import { AttackGraphView } from "../components/AttackGraphView";

interface Props {
  overview: SOC_Overview | null;
  agents: Agent[];
  events: EventItem[];
  onSelectPage: (p: string) => void;
  onKillAgent: (agent: Agent) => void;
  onRefresh: () => void;
}

export const OverviewPage: React.FC<Props> = ({
  overview,
  agents,
  events,
  onSelectPage,
  onKillAgent,
  onRefresh
}) => {
  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SOC CONTROL PLANE</div>
          <h1>Security Command Center</h1>
          <p>Real-time autonomous AI agent surveillance, Zero-Trust policy enforcement, and threat mitigation.</p>
        </div>
        <div className="action-buttons">
          <button className="secondary-button" onClick={onRefresh}>
            <RefreshCw size={15} /> Refresh
          </button>
          <button className="primary-button" onClick={() => onSelectPage("Agents")}>
            <Plus size={15} /> Register Agent
          </button>
        </div>
      </div>

      {/* Banner */}
      <div className="banner cyber-banner">
        <div className="banner-icon">
          <Bot size={24} />
        </div>
        <div className="banner-copy">
          <strong>AgentShield Zero-Trust Enforcement Active</strong>
          <p>Tagline: "Who Controls the AI?" · All agent tool invocations, prompts, and egress payloads are monitored and cryptographically audited.</p>
        </div>
        <div className="banner-status">
          <span className="pulse" />
          <span>Surveillance Live</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon blue"><Bot size={18}/></div>
          <div className="stat-label">Registered Agents</div>
          <div className="stat-value">{overview?.total_agents ?? "—"}</div>
          <div className="stat-detail">{overview?.active_agents ?? 0} active in control plane</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon violet"><Activity size={18}/></div>
          <div className="stat-label">Recorded Events</div>
          <div className="stat-value">{overview?.total_events ?? "—"}</div>
          <div className="stat-detail">Cryptographically verified</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon red"><ShieldAlert size={18}/></div>
          <div className="stat-label">Blocked Invocations</div>
          <div className="stat-value">{overview?.blocked_actions ?? "—"}</div>
          <div className="stat-detail">Zero-Trust policy stops</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon amber"><Clock3 size={18}/></div>
          <div className="stat-label">Pending Approvals</div>
          <div className="stat-value">{overview?.pending_approvals ?? "—"}</div>
          <div className="stat-detail">Human review required</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon red"><AlertTriangle size={18}/></div>
          <div className="stat-label">Open Incidents</div>
          <div className="stat-value">{overview?.open_incidents ?? 0}</div>
          <div className="stat-detail">Active investigations</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon amber"><Crosshair size={18}/></div>
          <div className="stat-label">Canary Tripwires</div>
          <div className="stat-value">{overview?.canary_trips ?? 0}</div>
          <div className="stat-detail">Breach honeytokens</div>
        </div>
      </div>

      {/* Two Column Layout: Agent Inventory & Recent Events */}
      <div className="two-col">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Agent Posture & Trust</h2>
              <p>Active agents and risk scores</p>
            </div>
            <button className="text-button" onClick={() => onSelectPage("Agents")}>
              View All <ArrowUpRight size={13} />
            </button>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>AGENT</th>
                  <th>STATUS</th>
                  <th>RISK</th>
                  <th>TRUST</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {agents.slice(0, 5).map(a => (
                  <tr key={a.id}>
                    <td>
                      <strong>{a.name}</strong>
                      <div className="subtext">{a.id}</div>
                    </td>
                    <td>
                      <span className={`badge ${a.status.toLowerCase()}`}>{a.status}</span>
                    </td>
                    <td>
                      <div className="risk-wrap">
                        <div className="risk-track">
                          <div
                            className={`risk-fill ${a.risk_score >= 70 ? "danger" : a.risk_score >= 40 ? "warning" : "safe"}`}
                            style={{ width: `${a.risk_score}%` }}
                          />
                        </div>
                        <span>{a.risk_score}/100</span>
                      </div>
                    </td>
                    <td>
                      <span className="trust-indicator">{a.trust_score ?? 90}%</span>
                    </td>
                    <td>
                      {a.status === "ACTIVE" ? (
                        <button className="kill-button" onClick={() => onKillAgent(a)}>Kill</button>
                      ) : (
                        <span className="subtext">Quarantined</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Telemetry Event Stream</h2>
              <p>Latest evaluated actions</p>
            </div>
            <button className="text-button" onClick={() => onSelectPage("Real-Time Monitor")}>
              Monitor <ArrowUpRight size={13} />
            </button>
          </div>
          <div className="event-list">
            {events.slice(0, 5).map(e => (
              <div key={e.id} className="event-row">
                <div className={`event-symbol ${e.decision.toLowerCase()}`}>
                  {e.decision === "ALLOW" ? <CheckCircle2 size={16}/> : <XCircle size={16}/>}
                </div>
                <div className="event-copy">
                  <strong>{e.action} <span>· {e.target}</span></strong>
                  <small>{e.agent_id} · Risk {e.risk_score} · {new Date(e.created_at).toLocaleTimeString()}</small>
                  <p>{e.reason}</p>
                </div>
                <span className={`badge ${e.decision.toLowerCase()}`}>{e.decision}</span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
};
