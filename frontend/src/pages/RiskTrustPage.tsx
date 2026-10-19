import React, { useState, useEffect } from "react";
import { TrendingUp, ShieldCheck, AlertTriangle, ArrowRight, RefreshCw } from "lucide-react";
import { RiskTrendChart } from "../components/RiskTrendChart";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
}

export const RiskTrustPage: React.FC<Props> = ({ agents }) => {
  const [trends, setTrends] = useState<any>(null);
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || "agent-finance-01");
  const [forecast, setForecast] = useState<any>(null);

  async function fetchTrends() {
    try {
      const data = await request<any>("/api/analytics/risk-trends");
      setTrends(data);
    } catch (err) {
      console.error(err);
    }
  }

  async function fetchForecast(agentId: string) {
    try {
      const data = await request<any>(`/api/analytics/forecast/${agentId}`);
      setForecast(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchTrends();
  }, []);

  useEffect(() => {
    if (selectedAgentId) {
      fetchForecast(selectedAgentId);
    }
  }, [selectedAgentId]);

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">RISK & TRUST ANALYTICS</div>
          <h1>Dynamic Risk & Continuous Trust Intelligence</h1>
          <p>Explainable risk score calculation (0–100), trust score decay tracking, and predictive next-action forecasting.</p>
        </div>
        <button className="secondary-button" onClick={() => { fetchTrends(); fetchForecast(selectedAgentId); }}>
          <RefreshCw size={15} /> Refresh Analytics
        </button>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Risk Score vs. Continuous Trust Trajectory</h2>
            <p>Chronological curve of recent evaluated decisions</p>
          </div>
        </div>
        <div className="chart-padding">
          <RiskTrendChart
            points={trends?.history || []}
            currentAvgRisk={trends?.current_avg_risk || 15}
            currentAvgTrust={trends?.current_avg_trust || 92}
          />
        </div>
      </section>

      {/* Next-Action Forecasting (Feature AF & V) */}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Next-Action Probabilistic Forecasting (Feature AF)</h2>
            <p>Projected next 2-3 probable tool calls and risk estimates</p>
          </div>
          <div className="select-wrap">
            <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
              {agents.map(a => (
                <option key={a.id} value={a.id}>{a.name} ({a.id})</option>
              ))}
            </select>
          </div>
        </div>

        {forecast ? (
          <div className="forecast-body">
            <div className="stat-row">
              <div className="stat-pill">
                Risk Trend: <strong>{forecast.predictive_risk?.trend}</strong>
              </div>
              <div className="stat-pill">
                Forecasted Risk (Next 1h): <strong>{forecast.predictive_risk?.predicted_risk_next_1h}/100</strong>
              </div>
              <div className="stat-pill">
                Uncertainty Interval: <strong>[{forecast.predictive_risk?.uncertainty_interval?.join(" - ")}]</strong>
              </div>
            </div>

            <h3>Projected Next Actions</h3>
            <div className="forecast-cards-grid">
              {(forecast.forecasted_actions || []).map((f: any, i: number) => (
                <div key={i} className="forecast-card">
                  <div className="forecast-prob">{(f.probability * 100).toFixed(0)}% Probability</div>
                  <strong>Action: {f.action}</strong>
                  <p>Estimated Risk: {f.estimated_risk}/100</p>
                  <small className="muted">{f.rationale}</small>
                  {f.requires_human_approval && (
                    <span className="badge warning">Will Trigger Human Approval</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="empty-inline">Select an agent above to view forecasted actions.</div>
        )}
      </section>
    </div>
  );
};
