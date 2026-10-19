import React, { useState, useEffect } from "react";
import { AlertTriangle, ShieldAlert, CheckCircle2, RefreshCw, X, Shield, FileText } from "lucide-react";
import { Incident } from "../types";
import { request } from "../api";

interface Props {
  onSelectIncidentReport?: (incId: number) => void;
}

export const IncidentsPage: React.FC<Props> = ({ onSelectIncidentReport }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedInc, setSelectedInc] = useState<Incident | null>(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);

  async function fetchIncidents() {
    try {
      const data = await request<Incident[]>("/api/incidents");
      setIncidents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchIncidents();
  }, []);

  async function handleStatusChange(id: number, newStatus: string) {
    try {
      await request(`/api/incidents/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus })
      });
      fetchIncidents();
      if (selectedInc && selectedInc.id === id) {
        setSelectedInc({ ...selectedInc, status: newStatus as any });
      }
    } catch (err) {
      alert("Status update failed");
    }
  }

  const filtered = incidents.filter(i => {
    if (statusFilter === "ALL") return true;
    return i.status === statusFilter;
  });

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SECURITY INCIDENT RESPONSE</div>
          <h1>Threat Alerts & Incidents</h1>
          <p>Triage high-risk security violations, autonomous response playbook executions, and evidence chains.</p>
        </div>
        <button className="secondary-button" onClick={fetchIncidents}>
          <RefreshCw size={15} /> Refresh Incidents
        </button>
      </div>

      <div className="filter-bar">
        <div className="filter-group">
          <button className={`pill-btn ${statusFilter === "ALL" ? "active" : ""}`} onClick={() => setStatusFilter("ALL")}>All ({incidents.length})</button>
          <button className={`pill-btn ${statusFilter === "OPEN" ? "active" : ""}`} onClick={() => setStatusFilter("OPEN")}>Open</button>
          <button className={`pill-btn ${statusFilter === "CONTAINED" ? "active" : ""}`} onClick={() => setStatusFilter("CONTAINED")}>Contained</button>
          <button className={`pill-btn ${statusFilter === "RESOLVED" ? "active" : ""}`} onClick={() => setStatusFilter("RESOLVED")}>Resolved</button>
        </div>
      </div>

      <section className="panel">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>INCIDENT ID</th>
                <th>SEVERITY</th>
                <th>TITLE</th>
                <th>AGENT</th>
                <th>STATUS</th>
                <th>ATTACK VECTOR</th>
                <th>TIMESTAMP</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(inc => (
                <tr key={inc.id}>
                  <td><strong>{inc.incident_number}</strong></td>
                  <td><span className={`badge ${inc.severity.toLowerCase()}`}>{inc.severity}</span></td>
                  <td>
                    <div className="clickable font-medium" onClick={() => setSelectedInc(inc)}>
                      {inc.title}
                    </div>
                  </td>
                  <td>{inc.agent_id || "System"}</td>
                  <td><span className={`badge ${inc.status.toLowerCase()}`}>{inc.status}</span></td>
                  <td><span className="code-tag">{inc.attack_vector || "Policy Violation"}</span></td>
                  <td>{new Date(inc.created_at).toLocaleString()}</td>
                  <td>
                    <div className="inline-actions">
                      <button className="secondary-button small-btn" onClick={() => setSelectedInc(inc)}>Inspect</button>
                      {inc.status !== "RESOLVED" && (
                        <button className="approve-button small-btn" onClick={() => handleStatusChange(inc.id, "RESOLVED")}>Resolve</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Incident Detail Modal */}
      {selectedInc && (
        <div className="modal-backdrop" onClick={() => setSelectedInc(null)}>
          <div className="modal-card wide-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <span className={`badge ${selectedInc.severity.toLowerCase()}`}>{selectedInc.severity} SEVERITY</span>
                <h2>{selectedInc.title}</h2>
                <small className="subtext">{selectedInc.incident_number} · Agent: {selectedInc.agent_id}</small>
              </div>
              <button className="icon-button" onClick={() => setSelectedInc(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body">
              <h3>Incident Summary</h3>
              <p>{selectedInc.summary}</p>

              <h3>Root Cause Analysis</h3>
              <div className="code-block-preview">{selectedInc.root_cause || "Direct prompt injection attempt and unpermitted egress destination."}</div>

              <h3>Digital Evidence</h3>
              <pre className="code-block-preview">{JSON.stringify(selectedInc.evidence || {}, null, 2)}</pre>

              <div className="modal-footer-actions">
                <div className="inline-actions">
                  <button className="secondary-button" onClick={() => handleStatusChange(selectedInc.id, "CONTAINED")}>Set Contained</button>
                  <button className="approve-button" onClick={() => handleStatusChange(selectedInc.id, "RESOLVED")}>Mark Resolved</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
