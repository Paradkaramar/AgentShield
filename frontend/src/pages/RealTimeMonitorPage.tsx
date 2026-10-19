import React, { useState, useEffect } from "react";
import { Activity, ShieldAlert, CheckCircle2, Clock3, Filter, Pause, Play, RefreshCw } from "lucide-react";
import { EventItem } from "../types";
import { request } from "../api";

export const RealTimeMonitorPage: React.FC = () => {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [isLive, setIsLive] = useState(true);
  const [loading, setLoading] = useState(true);

  async function fetchEvents() {
    try {
      const data = await request<EventItem[]>("/api/events?limit=150");
      setEvents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchEvents();
    if (!isLive) return;
    const interval = window.setInterval(fetchEvents, 3000);
    return () => window.clearInterval(interval);
  }, [isLive]);

  const filtered = events.filter(e => {
    if (filter === "ALL") return true;
    return e.decision === filter;
  });

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">LIVE TELEMETRY STREAM</div>
          <h1>Real-Time Activity Monitor</h1>
          <p>Continuous observation of all instrumented AI agent tool invocations, network requests, and security policy outcomes.</p>
        </div>
        <div className="action-buttons">
          <button className={`secondary-button ${isLive ? "active-toggle" : ""}`} onClick={() => setIsLive(v => !v)}>
            {isLive ? <Pause size={15}/> : <Play size={15}/>} {isLive ? "Live Stream Active" : "Stream Paused"}
          </button>
          <button className="icon-button" onClick={fetchEvents} title="Refresh Now">
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      <div className="filter-bar">
        <div className="filter-group">
          <Filter size={15} />
          <button className={`pill-btn ${filter === "ALL" ? "active" : ""}`} onClick={() => setFilter("ALL")}>All ({events.length})</button>
          <button className={`pill-btn ${filter === "ALLOW" ? "active" : ""}`} onClick={() => setFilter("ALLOW")}>Allowed</button>
          <button className={`pill-btn ${filter === "BLOCK" ? "active" : ""}`} onClick={() => setFilter("BLOCK")}>Blocked</button>
          <button className={`pill-btn ${filter === "ASK_HUMAN" ? "active" : ""}`} onClick={() => setFilter("ASK_HUMAN")}>Pending Review</button>
        </div>
      </div>

      <section className="panel">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>AGENT ID</th>
                <th>ACTION</th>
                <th>TARGET / RESOURCE</th>
                <th>DECISION</th>
                <th>RISK</th>
                <th>LATENCY</th>
                <th>REASON & SIGNALS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(e => (
                <tr key={e.id}>
                  <td>{new Date(e.created_at).toLocaleTimeString()}</td>
                  <td><strong>{e.agent_id}</strong></td>
                  <td><span className="code-tag">{e.action}</span></td>
                  <td className="target-cell">{e.target}</td>
                  <td><span className={`badge ${e.decision.toLowerCase()}`}>{e.decision}</span></td>
                  <td>
                    <div className="risk-wrap">
                      <div className="risk-track">
                        <div className={`risk-fill ${e.risk_score >= 70 ? "danger" : e.risk_score >= 40 ? "warning" : "safe"}`} style={{ width: `${e.risk_score}%` }} />
                      </div>
                      <span>{e.risk_score}</span>
                    </div>
                  </td>
                  <td>{e.latency_ms ?? 18}ms</td>
                  <td className="reason-cell">
                    <div>{e.reason}</div>
                    {e.payload_sanitized && <small className="payload-preview">Preview: {e.payload_sanitized.substring(0, 80)}...</small>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
