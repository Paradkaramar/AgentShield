import React, { useState, useEffect } from "react";
import { Compass, RefreshCw, Plus, Search, ShieldCheck, AlertCircle } from "lucide-react";
import { ShadowAIDetection } from "../types";
import { request } from "../api";

interface Props {
  onRefreshAll: () => void;
}

export const ShadowAiPage: React.FC<Props> = ({ onRefreshAll }) => {
  const [detections, setDetections] = useState<ShadowAIDetection[]>([]);
  const [busy, setBusy] = useState(false);

  async function fetchShadowAi() {
    try {
      const data = await request<ShadowAIDetection[]>("/api/shadow-ai");
      setDetections(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchShadowAi();
  }, []);

  async function handleScan() {
    setBusy(true);
    try {
      const res = await request<any>("/api/shadow-ai/scan", { method: "POST" });
      alert(`Telemetry Scan Complete: Discovered ${res.new_detections} rogue or uninstrumented service(s).`);
      fetchShadowAi();
      onRefreshAll();
    } catch (err) {
      alert("Telemetry scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleRegister(id: number) {
    try {
      const res = await request<any>(`/api/shadow-ai/${id}/register`, { method: "POST" });
      alert(res.message);
      fetchShadowAi();
      onRefreshAll();
    } catch (err) {
      alert("Registration failed");
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">UNMANAGED AI DISCOVERY</div>
          <h1>Shadow AI & Unregistered Agents (Feature Q & AE)</h1>
          <p>Scan network telemetry, process logs, and uninstrumented API egress to detect rogue AI processes and LLM connections.</p>
        </div>
        <div className="action-buttons">
          <button className="primary-button" onClick={handleScan} disabled={busy}>
            <Compass size={15} /> Run Telemetry Scan
          </button>
        </div>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Discovered Unregistered AI Services ({detections.length})</h2>
            <p>Telemetry collector findings</p>
          </div>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>PROCESS NAME</th>
                <th>DESTINATION ENDPOINT</th>
                <th>AUTH SIGNATURE</th>
                <th>CONFIDENCE</th>
                <th>DETECTED EVIDENCE</th>
                <th>STATUS</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {detections.map(d => (
                <tr key={d.id}>
                  <td><strong>{d.process_name}</strong></td>
                  <td><span className="code-tag">{d.destination_ip_host}</span></td>
                  <td>{d.token_signature}</td>
                  <td>{(d.confidence * 100).toFixed(0)}%</td>
                  <td className="reason-cell">{d.evidence}</td>
                  <td><span className={`badge ${d.status.toLowerCase()}`}>{d.status}</span></td>
                  <td>
                    {d.status === "DETECTED" ? (
                      <button className="approve-button small-btn" onClick={() => handleRegister(d.id)}>
                        <Plus size={12} /> Register Agent
                      </button>
                    ) : (
                      <span className="subtext">Onboarded</span>
                    )}
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
