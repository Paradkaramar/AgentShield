import React, { useState, useEffect } from "react";
import { Activity, AlertTriangle, ShieldCheck, RefreshCw } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
}

export const BehaviorDriftPage: React.FC<Props> = ({ agents }) => {
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || "agent-finance-01");
  const [driftReport, setDriftReport] = useState<any>(null);

  async function checkDrift() {
    try {
      const data = await request<any>(`/api/agents/${selectedAgentId}/drift`);
      setDriftReport(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    if (selectedAgentId) checkDrift();
  }, [selectedAgentId]);

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">STATISTICAL ANOMALY DETECTION</div>
          <h1>Behavioral Signature & Concept Drift (Feature E & AC)</h1>
          <p>Detect statistical deviations from established baselines in invocation frequency, tool call sequences, data egress volume, and destination endpoints.</p>
        </div>
        <div className="select-wrap">
          <label>Agent Baseline:</label>
          <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
            {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.id})</option>)}
          </select>
        </div>
      </div>

      <div className="two-col">
        {/* Permission Drift Section */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Permission Drift Analysis (Feature R)</h2>
              <p>Compares active privileges with approved security baseline</p>
            </div>
            <button className="icon-button" onClick={checkDrift}><RefreshCw size={14}/></button>
          </div>
          <div className="result-body">
            {driftReport ? (
              <div>
                <div className={`decision-card ${driftReport.permission_drift?.has_drift ? "block" : "allow"}`}>
                  <strong>{driftReport.permission_drift?.summary}</strong>
                  <small>Severity: {driftReport.permission_drift?.drift_severity}</small>
                </div>

                <h3>Added Privileges (Unauthorized Drift)</h3>
                {Object.keys(driftReport.permission_drift?.added_privileges || {}).length === 0 ? (
                  <div className="empty-inline"><ShieldCheck size={16}/> No unauthorized privilege additions detected.</div>
                ) : (
                  <div className="drift-list">
                    {Object.entries(driftReport.permission_drift?.added_privileges).map(([k, v]: any) => (
                      <div key={k} className="drift-row">
                        <AlertTriangle size={15} color="#ff7675" />
                        <span>Action <strong>{k.toUpperCase()}</strong>: Added {v.join(", ")}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-inline">Loading drift report...</div>
            )}
          </div>
        </section>

        {/* System Prompt Drift Section */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>System Prompt & Instruction Drift (Feature AK)</h2>
              <p>Compares active instructions with cryptographically signed baseline</p>
            </div>
          </div>
          <div className="result-body">
            {driftReport ? (
              <div>
                <div className={`decision-card ${driftReport.system_prompt_drift?.has_tampering ? "block" : "allow"}`}>
                  <strong>Status: {driftReport.system_prompt_drift?.status}</strong>
                  <small>Drift: {driftReport.system_prompt_drift?.drift_percentage}% · Similarity: {(driftReport.system_prompt_drift?.similarity_ratio * 100).toFixed(1)}%</small>
                </div>

                <h3>Diff Analysis Preview</h3>
                <div className="code-block-preview">
                  {driftReport.system_prompt_drift?.unified_diff?.length > 0 ? (
                    driftReport.system_prompt_drift.unified_diff.join("\n")
                  ) : (
                    "No differences. Active system prompt exactly matches approved baseline."
                  )}
                </div>
              </div>
            ) : (
              <div className="empty-inline">Loading instruction drift...</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};
