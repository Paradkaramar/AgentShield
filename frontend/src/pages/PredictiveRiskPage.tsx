import React, { useState, useEffect } from "react";
import { TrendingUp, RefreshCw, AlertCircle, ShieldAlert, CheckCircle2 } from "lucide-react";
import { Agent } from "../types";
import { request } from "../api";

interface Props {
  agents: Agent[];
}

export const PredictiveRiskPage: React.FC<Props> = ({ agents }) => {
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || "agent-finance-01");
  const [forecastData, setForecastData] = useState<any>(null);

  async function fetchForecast() {
    try {
      const data = await request<any>(`/api/analytics/forecast/${selectedAgentId}`);
      setForecastData(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    if (selectedAgentId) fetchForecast();
  }, [selectedAgentId]);

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">PREDICTIVE RISK ENGINE</div>
          <h1>Predictive Risk Forecasting (Feature V)</h1>
          <p>Estimate near-future security risk from recent event slopes, agent plans, and permission breadth. Evaluates uncertainty intervals and future trend trajectories.</p>
        </div>
        <div className="select-wrap">
          <label>Agent:</label>
          <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
            {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.id})</option>)}
          </select>
        </div>
      </div>

      <div className="two-col">
        {/* Trend Forecast Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Near-Future Risk Estimation</h2>
              <p>1-Hour Projection with Uncertainty Margin</p>
            </div>
            <button className="icon-button" onClick={fetchForecast}><RefreshCw size={14}/></button>
          </div>
          <div className="result-body">
            {forecastData ? (
              <div>
                <div className="decision-card allow">
                  <span>PROJECTED RISK (T+1H)</span>
                  <strong>{forecastData.predictive_risk?.predicted_risk_next_1h}/100</strong>
                  <small>Trend Direction: {forecastData.predictive_risk?.trend} · Confidence: {(forecastData.predictive_risk?.confidence * 100).toFixed(0)}%</small>
                </div>

                <h3>Uncertainty Margin</h3>
                <div className="stat-pill">
                  Estimated Confidence Interval: <strong>[{forecastData.predictive_risk?.uncertainty_interval?.join(" - ")}]</strong>
                </div>

                <h3>Contributing Model Factors</h3>
                <ul>
                  {(forecastData.predictive_risk?.contributing_factors || []).map((factor: string, i: number) => (
                    <li key={i}>{factor}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="empty-inline">Loading predictive forecast...</div>
            )}
          </div>
        </section>

        {/* Next Probable Actions */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Probabilistic Tool-Call Forecasts (Feature AF)</h2>
              <p>Anticipated next steps from Markov transition modeling</p>
            </div>
          </div>
          <div className="result-body">
            <div className="forecast-cards-grid">
              {(forecastData?.forecasted_actions || []).map((f: any, i: number) => (
                <div key={i} className="forecast-card">
                  <div className="forecast-prob">{(f.probability * 100).toFixed(0)}% Likelihood</div>
                  <strong>Tool Action: {f.action}</strong>
                  <p>Estimated Risk Score: {f.estimated_risk}/100</p>
                  <small className="muted">{f.rationale}</small>
                  {f.requires_human_approval && (
                    <span className="badge warning">Will Trigger Human Approval</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
