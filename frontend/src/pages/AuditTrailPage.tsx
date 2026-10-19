import React, { useState, useEffect } from "react";
import { History, ShieldCheck, Download, RefreshCw, CheckCircle2, AlertTriangle, Key } from "lucide-react";
import { AuditRecord } from "../types";
import { request } from "../api";

export const AuditTrailPage: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [integrityStatus, setIntegrityStatus] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);

  async function fetchAudit() {
    try {
      const data = await request<AuditRecord[]>("/api/audit");
      setRecords(data);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleVerifyIntegrity() {
    setVerifying(true);
    try {
      const res = await request<any>("/api/audit/verify");
      setIntegrityStatus(res);
    } catch (err) {
      alert("Verification failed");
    } finally {
      setVerifying(false);
    }
  }

  useEffect(() => {
    fetchAudit();
  }, []);

  function handleExport() {
    const blob = new Blob([JSON.stringify(records, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `agentshield_audit_ledger_${Date.now()}.json`;
    a.click();
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">IMMUTABLE COMPLIANCE LEDGER</div>
          <h1>Cryptographic Audit Trail (Feature L)</h1>
          <p>Every security decision, policy update, approval, and emergency kill-switch activation is cryptographically hashed in a SHA-256 blockchain-style ledger.</p>
        </div>
        <div className="action-buttons">
          <button className="primary-button" onClick={handleVerifyIntegrity} disabled={verifying}>
            <ShieldCheck size={15} /> Verify Cryptographic Integrity
          </button>
          <button className="secondary-button" onClick={handleExport}>
            <Download size={15} /> Export JSON Ledger
          </button>
        </div>
      </div>

      {integrityStatus && (
        <div className={`banner ${integrityStatus.chain_intact ? "cyber-banner" : "alert error"}`}>
          <div className="banner-icon">
            {integrityStatus.chain_intact ? <CheckCircle2 size={24} color="#42d69b"/> : <AlertTriangle size={24} color="#ff7675"/>}
          </div>
          <div className="banner-copy">
            <strong>Audit Ledger Cryptographic Integrity: {integrityStatus.status}</strong>
            <p>
              Verified {integrityStatus.records_verified} sequential records from Genesis block.
              {integrityStatus.chain_intact
                ? " No tampering or chain truncation detected. All cryptographic hashes match."
                : " WARNING: Cryptographic hash discrepancy identified in audit records!"}
            </p>
          </div>
        </div>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Tamper-Evident Audit Ledger ({records.length})</h2>
            <p>SHA-256 Linked Ledger Entries</p>
          </div>
          <button className="icon-button" onClick={fetchAudit}><RefreshCw size={14}/></button>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>ACTOR (WHO)</th>
                <th>ACTION (WHAT)</th>
                <th>RESOURCE</th>
                <th>CURRENT SHA-256 HASH</th>
                <th>PREVIOUS BLOCK HASH</th>
              </tr>
            </thead>
            <tbody>
              {records.map(r => (
                <tr key={r.id}>
                  <td>{new Date(r.timestamp).toLocaleString()}</td>
                  <td><strong>{r.actor}</strong></td>
                  <td><span className="code-tag">{r.action}</span></td>
                  <td>{r.resource}</td>
                  <td><code>{r.current_hash?.substring(0, 16)}...</code></td>
                  <td><code className="muted">{r.prev_hash?.substring(0, 16)}...</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
