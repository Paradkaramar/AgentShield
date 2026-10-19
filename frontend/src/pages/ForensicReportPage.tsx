import React, { useState, useEffect } from "react";
import { FileText, Download, Printer, Shield, CheckCircle2 } from "lucide-react";
import { Incident } from "../types";
import { request } from "../api";

export const ForensicReportPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<number | null>(null);
  const [report, setReport] = useState<any>(null);

  async function fetchIncidents() {
    try {
      const data = await request<Incident[]>("/api/incidents");
      setIncidents(data);
      if (data.length > 0) {
        setSelectedIncId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function fetchReport(id: number) {
    try {
      const data = await request<any>(`/api/forensics/report/${id}`);
      setReport(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchIncidents();
  }, []);

  useEffect(() => {
    if (selectedIncId) {
      fetchReport(selectedIncId);
    }
  }, [selectedIncId]);

  function downloadJSON() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.report_id}.json`;
    a.click();
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">COMPROMISED AGENT FORENSICS</div>
          <h1>Incident Forensic Dossier (Feature AN)</h1>
          <p>Export downloadable and printable forensic dossiers with cryptographic evidence hashes, chronological timelines, and root cause conclusions.</p>
        </div>
        <div className="action-buttons">
          <button className="primary-button" onClick={downloadJSON} disabled={!report}>
            <Download size={15} /> Export JSON Dossier
          </button>
          <button className="secondary-button" onClick={() => window.print()} disabled={!report}>
            <Printer size={15} /> Print / Save as PDF
          </button>
        </div>
      </div>

      <div className="select-row-banner">
        <label>Select Incident for Forensic Report:</label>
        <select value={selectedIncId || ""} onChange={e => setSelectedIncId(Number(e.target.value))}>
          {incidents.map(i => (
            <option key={i.id} value={i.id}>{i.incident_number} — {i.title}</option>
          ))}
        </select>
      </div>

      {report && (
        <section className="panel printable-report">
          <div className="report-header-banner">
            <div>
              <div className="eyebrow">AGENTSHIELD FORENSIC DOSSIER</div>
              <h2>{report.incident_summary?.title}</h2>
              <small className="subtext">
                Dossier ID: {report.report_id} · Generated: {new Date(report.generated_at).toLocaleString()}
              </small>
            </div>
            <div className="hash-stamp">
              <Shield size={16} />
              <span>SHA-256 INTEGRITY HASH:</span>
              <code>{report.integrity_sha256}</code>
            </div>
          </div>

          <div className="result-body">
            <h3>1. Incident Overview & Containment Posture</h3>
            <div className="stat-row">
              <div className="stat-pill">Severity: <strong>{report.incident_summary?.severity}</strong></div>
              <div className="stat-pill">Status: <strong>{report.incident_summary?.status}</strong></div>
              <div className="stat-pill">Root Cause: <strong>{report.incident_summary?.root_cause}</strong></div>
            </div>

            <h3>2. Compromised Agent Identity Snapshot</h3>
            <div className="table-scroll">
              <table>
                <tbody>
                  <tr><td>Agent ID:</td><td><strong>{report.compromised_agent?.id}</strong></td></tr>
                  <tr><td>Agent Name:</td><td>{report.compromised_agent?.name}</td></tr>
                  <tr><td>Model Spec:</td><td>{report.compromised_agent?.model}</td></tr>
                  <tr><td>Current Status:</td><td><span className="badge danger">{report.compromised_agent?.status}</span></td></tr>
                </tbody>
              </table>
            </div>

            <h3>3. Reconstructed Chronological Timeline</h3>
            <div className="timeline-steps">
              {(report.reconstructed_timeline?.timeline || []).map((step: any) => (
                <div key={step.step} className="timeline-step-card">
                  <div className="step-header">
                    <strong>Step {step.step} · {step.action} on {step.target}</strong>
                    <span className={`badge ${step.decision?.toLowerCase()}`}>{step.decision}</span>
                  </div>
                  <p>{step.captured_fact}</p>
                </div>
              ))}
            </div>

            <h3>4. Forensic Conclusions & Containment Recommendations</h3>
            <ul>
              {(report.conclusions || []).map((c: string, idx: number) => (
                <li key={idx}><strong>{c}</strong></li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  );
};
