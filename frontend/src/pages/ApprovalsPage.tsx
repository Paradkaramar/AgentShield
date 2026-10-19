import React, { useState } from "react";
import { CheckCircle2, XCircle, Clock3, RefreshCw, ShieldAlert } from "lucide-react";
import { Approval } from "../types";
import { request } from "../api";

interface Props {
  approvals: Approval[];
  onRefresh: () => void;
}

export const ApprovalsPage: React.FC<Props> = ({ approvals, onRefresh }) => {
  const [filter, setFilter] = useState("PENDING");
  const [busy, setBusy] = useState(false);

  async function handleDecision(id: number, decision: "APPROVE" | "REJECT") {
    setBusy(true);
    try {
      await request(`/api/approvals/${id}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision, reason: `Human reviewer ${decision.toLowerCase()}d action` })
      });
      onRefresh();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Decision failed");
    } finally {
      setBusy(false);
    }
  }

  const filtered = approvals.filter(a => {
    if (filter === "ALL") return true;
    return a.status === filter;
  });

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">HUMAN-IN-THE-LOOP CONTROL</div>
          <h1>Approval Queue</h1>
          <p>Review sensitive or elevated-risk AI agent operations requiring explicit authorized human sign-off.</p>
        </div>
        <button className="secondary-button" onClick={onRefresh}>
          <RefreshCw size={15} /> Refresh Queue
        </button>
      </div>

      <div className="filter-bar">
        <div className="filter-group">
          <button className={`pill-btn ${filter === "PENDING" ? "active" : ""}`} onClick={() => setFilter("PENDING")}>
            Pending ({approvals.filter(a => a.status === "PENDING").length})
          </button>
          <button className={`pill-btn ${filter === "ALL" ? "active" : ""}`} onClick={() => setFilter("ALL")}>
            All History ({approvals.length})
          </button>
        </div>
      </div>

      <section className="panel">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>AGENT ID</th>
                <th>REQUESTED ACTION</th>
                <th>TARGET / DESTINATION</th>
                <th>RISK</th>
                <th>JUSTIFICATION & SIGNALS</th>
                <th>STATUS</th>
                <th>SUBMITTED</th>
                <th>DECISION</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty-cell">
                    <Clock3 size={18} /> No approval requests in this view.
                  </td>
                </tr>
              ) : (
                filtered.map(a => (
                  <tr key={a.id}>
                    <td><strong>{a.agent_id}</strong></td>
                    <td><span className="code-tag">{a.action}</span></td>
                    <td className="target-cell">{a.target}</td>
                    <td>
                      <div className="risk-wrap">
                        <div className="risk-track">
                          <div className={`risk-fill ${a.risk_score >= 70 ? "danger" : "warning"}`} style={{ width: `${a.risk_score}%` }} />
                        </div>
                        <span>{a.risk_score}</span>
                      </div>
                    </td>
                    <td className="reason-cell">
                      <div>{a.reason}</div>
                      {a.payload && <small className="payload-preview">Preview: {a.payload.substring(0, 80)}...</small>}
                    </td>
                    <td><span className={`badge ${a.status.toLowerCase()}`}>{a.status}</span></td>
                    <td>{new Date(a.created_at).toLocaleTimeString()}</td>
                    <td>
                      {a.status === "PENDING" ? (
                        <div className="inline-actions">
                          <button className="approve-button" disabled={busy} onClick={() => handleDecision(a.id, "APPROVE")}>
                            Approve
                          </button>
                          <button className="reject-button" disabled={busy} onClick={() => handleDecision(a.id, "REJECT")}>
                            Reject
                          </button>
                        </div>
                      ) : (
                        <span className="subtext">{a.approver || "System"}</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
