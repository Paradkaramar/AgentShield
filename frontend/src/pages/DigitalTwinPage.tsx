import React, { useState, useEffect } from "react";
import { Cpu, Play, RefreshCw, Layers, CheckCircle2, AlertCircle } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
}

export const DigitalTwinPage: React.FC<Props> = ({ agents }) => {
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || "agent-finance-01");
  const [snapshot, setSnapshot] = useState<any>(null);
  const [replayMode, setReplayMode] = useState("STRICT");
  const [replayResult, setReplayResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function fetchTwin() {
    try {
      const data = await request<any>(`/api/digital-twin/${selectedAgentId}`);
      setSnapshot(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    if (selectedAgentId) fetchTwin();
  }, [selectedAgentId]);

  async function handleReplay() {
    setBusy(true);
    try {
      const res = await request<any>("/api/digital-twin/replay", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgentId,
          alternative_policy_mode: replayMode
        })
      });
      setReplayResult(res);
    } catch (err) {
      alert("Replay failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SANDBOX SIMULATION</div>
          <h1>Agent Digital Twin & Sandbox Replay (Feature X)</h1>
          <p>Maintain versioned state snapshots of agent configuration, permissions, and tool-call history. Reconstruct recorded sessions and evaluate counterfactual policy outcomes.</p>
        </div>
        <div className="select-wrap">
          <label>Select Agent Digital Twin:</label>
          <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
            {agents.map(a => (
              <option key={a.id} value={a.id}>{a.name} ({a.id})</option>
            ))}
          </select>
        </div>
      </div>

      <div className="two-col">
        {/* Snapshot Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Digital Twin State Snapshot</h2>
              <p>Versioned configuration & permission state</p>
            </div>
            <button className="icon-button" onClick={fetchTwin}><RefreshCw size={14}/></button>
          </div>
          <div className="result-body">
            {snapshot ? (
              <div>
                <div className="stat-row">
                  <div className="stat-pill">Version: <strong>{snapshot.version}</strong></div>
                  <div className="stat-pill">Status: <strong>{snapshot.configuration?.status}</strong></div>
                  <div className="stat-pill">Trust: <strong>{snapshot.configuration?.trust_score}/100</strong></div>
                </div>
                <h3>Active Tools</h3>
                <div className="tool-tags">
                  {(snapshot.configuration?.tools || []).map((t: string) => <span key={t}>{t}</span>)}
                </div>
                <h3>Recent Traces ({snapshot.recorded_trace_count})</h3>
                <div className="traces-list">
                  {(snapshot.recent_traces || []).map((tr: any, idx: number) => (
                    <div key={idx} className="trace-item">
                      <span>{tr.action} on <strong>{tr.target}</strong></span>
                      <span className={`badge ${tr.decision?.toLowerCase()}`}>{tr.decision}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="empty-inline">Loading twin snapshot...</div>
            )}
          </div>
        </section>

        {/* Replay Controls Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Sandbox Replay Engine</h2>
              <p>Simulate traces against alternative policy configurations</p>
            </div>
          </div>
          <div className="stack-form">
            <label>
              Alternative Policy Mode
              <select value={replayMode} onChange={e => setReplayMode(e.target.value)}>
                <option value="STRICT">Strict Zero-Trust (Block all high impact, ask human for writes)</option>
                <option value="PERMISSIVE">Permissive Mode (Allow all read/write)</option>
              </select>
            </label>
            <button className="primary-button" onClick={handleReplay} disabled={busy}>
              <Play size={15} /> Execute Sandbox Replay
            </button>
          </div>

          {replayResult && (
            <div className="result-body">
              <div className="decision-card allow">
                <strong>{replayResult.conclusion}</strong>
                <small>Divergences detected: {replayResult.policy_divergences}</small>
              </div>

              <h3>Trace Divergence Results</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>ACTION</th>
                      <th>TARGET</th>
                      <th>ORIGINAL DECISION</th>
                      <th>SIMULATED DECISION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {replayResult.results?.map((r: any, idx: number) => (
                      <tr key={idx}>
                        <td><strong>{r.action}</strong></td>
                        <td>{r.target}</td>
                        <td><span className={`badge ${r.original_decision?.toLowerCase()}`}>{r.original_decision}</span></td>
                        <td>
                          <span className={`badge ${r.simulated_decision?.toLowerCase()}`}>
                            {r.simulated_decision} {r.policy_outcome_diverged && "(CHANGED)"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
