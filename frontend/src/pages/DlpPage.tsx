import React, { useState } from "react";
import { Lock, Eye, ShieldCheck, ShieldAlert, CheckCircle2 } from "lucide-react";
import { request } from "../api";

export const DlpPage: React.FC = () => {
  const dlpRules = [
    { id: "us_ssn", pattern: "US Social Security Numbers", severity: "CRITICAL", default_action: "BLOCK", example: "999-12-3456" },
    { id: "credit_card", pattern: "Major Credit Card Numbers (Visa/MC/Amex)", severity: "CRITICAL", default_action: "BLOCK", example: "4111-2222-3333-4444" },
    { id: "aws_access_key", pattern: "AWS Cloud Access Key IDs", severity: "CRITICAL", default_action: "BLOCK", example: "AKIAIOSFODNN7EXAMPLE" },
    { id: "openai_api_key", pattern: "OpenAI Secret API Keys", severity: "CRITICAL", default_action: "BLOCK", example: "sk-proj-99214..." },
    { id: "private_key", pattern: "RSA / EC Asymmetric Private Key Blocks", severity: "CRITICAL", default_action: "BLOCK", example: "-----BEGIN RSA PRIVATE KEY-----" },
    { id: "jwt_token", pattern: "JSON Web Tokens (JWT)", severity: "HIGH", default_action: "REQUIRE_HUMAN_APPROVAL", example: "eyJhbGciOi..." },
    { id: "db_dump_sql", pattern: "SQL Table Drop / Dump Exfiltration", severity: "HIGH", default_action: "BLOCK", example: "DROP TABLE users;" },
  ];

  const [inputSample, setInputSample] = useState("Transfer funds for client with SSN 999-01-4412 and card 4111222233334444. Use key AKIA1234567890ABCDEF.");
  const [dlpResult, setDlpResult] = useState<any>(null);

  async function handleTestDlp() {
    try {
      const res = await request<any>("/api/actions/evaluate", {
        method: "POST",
        body: JSON.stringify({
          agent_id: "agent-finance-01",
          action: "READ",
          target: "internal:sandbox",
          payload: inputSample
        })
      });
      setDlpResult(res.dlp);
    } catch (err) {
      alert("DLP Scan Failed");
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">OUTBOUND EGRESS GUARD</div>
          <h1>Data Loss Prevention (DLP) Engine (Feature J)</h1>
          <p>Inspect outbound agent payloads before transmission. Detect, mask, and block sensitive personal, financial, and credential data.</p>
        </div>
      </div>

      <div className="two-col">
        {/* Rules Table */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Active DLP Detection Rules</h2>
              <p>Standard PII, financial, and credential patterns</p>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>RULE ID</th>
                  <th>PATTERN CATEGORY</th>
                  <th>SEVERITY</th>
                  <th>ENFORCEMENT</th>
                </tr>
              </thead>
              <tbody>
                {dlpRules.map(r => (
                  <tr key={r.id}>
                    <td><code>{r.id}</code></td>
                    <td><strong>{r.pattern}</strong></td>
                    <td><span className={`badge ${r.severity.toLowerCase()}`}>{r.severity}</span></td>
                    <td><span className="badge block">{r.default_action}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Live DLP Redaction Tester */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Live Payload DLP Redaction Tester</h2>
              <p>Test real-time masking of PII and credentials</p>
            </div>
          </div>
          <div className="stack-form">
            <label>
              Payload to Inspect:
              <textarea rows={4} value={inputSample} onChange={e => setInputSample(e.target.value)} />
            </label>
            <button className="primary-button" onClick={handleTestDlp}>
              <Eye size={15} /> Scan & Redact Payload
            </button>
          </div>

          {dlpResult && (
            <div className="result-body">
              <div className={`decision-card ${dlpResult.has_sensitive_data ? "block" : "allow"}`}>
                <strong>{dlpResult.has_sensitive_data ? "SENSITIVE DATA PATTERNS MATCHED" : "NO SENSITIVE DATA FOUND"}</strong>
                <small>{dlpResult.violations?.length || 0} sensitive elements identified</small>
              </div>

              <h3>Redacted Output Preview (Stored in Ledger)</h3>
              <div className="code-block-preview">{dlpResult.sanitized_preview}</div>

              {dlpResult.violations?.length > 0 && (
                <div className="dlp-violations-box">
                  <strong>Matched Violations:</strong>
                  <ul>
                    {dlpResult.violations.map((v: any, idx: number) => (
                      <li key={idx}>{v.description} — Count: {v.count}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
