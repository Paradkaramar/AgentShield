import React, { useState, useEffect } from "react";
import { Zap, ShieldCheck, ShieldAlert, Play, CheckCircle2, AlertTriangle } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
  onRefreshAll: () => void;
}

export const RedTeamPage: React.FC<Props> = ({ agents, onRefreshAll }) => {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || "");
  const [simulationResults, setSimulationResults] = useState<Record<string, any>>({});
  const [runningId, setRunningId] = useState<string | null>(null);

  async function fetchScenarios() {
    try {
      const data = await request<any[]>("/api/simulation/scenarios");
      setScenarios(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchScenarios();
  }, []);

  async function runScenario(scenarioId: string) {
    if (!selectedAgentId) return;
    setRunningId(scenarioId);
    try {
      const res = await request<any>("/api/simulation/run", {
        method: "POST",
        body: JSON.stringify({
          scenario_id: scenarioId,
          agent_id: selectedAgentId
        })
      });
      setSimulationResults(prev => ({ ...prev, [scenarioId]: res }));
      onRefreshAll();
    } catch (err) {
      alert("Simulation run failed");
    } finally {
      setRunningId(null);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">DEFENSIVE VALIDATION</div>
          <h1>Red-Team Simulation Laboratory (Feature T)</h1>
          <p>Execute safe, synthetic adversarial test cases against registered AI agents to validate Zero-Trust policy enforcement, prompt injection detection, and DLP controls.</p>
        </div>
        <div className="select-wrap">
          <label>Target Agent for Simulation:</label>
          <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
            {agents.map(a => (
              <option key={a.id} value={a.id}>{a.name} ({a.status})</option>
            ))}
          </select>
        </div>
      </div>

      <div className="scenarios-grid">
        {scenarios.map(s => {
          const res = simulationResults[s.id];
          const isRunning = runningId === s.id;

          return (
            <div key={s.id} className="scenario-card panel">
              <div className="scenario-top">
                <span className="badge category-badge">{s.category}</span>
                <strong>{s.name}</strong>
              </div>
              <p className="scenario-desc">{s.description}</p>
              <div className="scenario-payload">
                <small>Payload:</small>
                <code>{s.payload}</code>
              </div>
              <div className="scenario-meta">
                <span>Action: <strong>{s.action}</strong></span>
                <span>Target: <strong>{s.target}</strong></span>
              </div>

              <div className="scenario-footer">
                <button
                  className="primary-button small-btn"
                  onClick={() => runScenario(s.id)}
                  disabled={isRunning || !selectedAgentId}
                >
                  <Play size={13} /> {isRunning ? "Running..." : "Execute Simulation"}
                </button>

                {res && (
                  <div className={`sim-result-badge ${res.passed_defense ? "success" : "failed"}`}>
                    {res.passed_defense ? <CheckCircle2 size={15}/> : <ShieldAlert size={15}/>}
                    <span>{res.passed_defense ? "Mitigated (Blocked)" : "Bypassed"}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
