import React, { useState } from "react";
import { Terminal, Send, ShieldCheck, CheckCircle2, Lock, ArrowRight } from "lucide-react";
import { request } from "../api";

export const ToolProxyPage: React.FC = () => {
  const tools = [
    { id: "tool-db", name: "Database Connector", category: "database", risk_level: "HIGH", requires_approval: 1, allowed_destinations: ["postgres-internal.lan", "finance-db.lan"] },
    { id: "tool-files", name: "Local File Storage", category: "filesystem", risk_level: "MEDIUM", requires_approval: 0, allowed_destinations: ["/data/reports", "/tmp/sandbox"] },
    { id: "tool-email", name: "Corporate Mail Relay", category: "messaging", risk_level: "HIGH", requires_approval: 1, allowed_destinations: ["mail.company.com"] },
    { id: "tool-crm", name: "CRM Customer Records", category: "crm", risk_level: "CRITICAL", requires_approval: 1, allowed_destinations: ["crm.internal.corp"] },
    { id: "tool-browser", name: "Sandboxed Web Scraper", category: "network", risk_level: "MEDIUM", requires_approval: 0, allowed_destinations: ["*.wikipedia.org", "*.github.com", "*.arxiv.org"] },
    { id: "tool-shell", name: "Secure Command Runner", category: "cloud", risk_level: "CRITICAL", requires_approval: 1, allowed_destinations: ["localhost"] }
  ];

  const [testToolId, setTestToolId] = useState("tool-db");
  const [testAction, setTestAction] = useState("READ");
  const [testTarget, setTestTarget] = useState("finance-db.lan");
  const [testPayload, setTestPayload] = useState("SELECT total_revenue FROM q3_summary;");
  const [proxyOutput, setProxyOutput] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function handleExecuteProxy() {
    setBusy(true);
    try {
      const res = await request<any>("/api/actions/proxy", {
        method: "POST",
        body: JSON.stringify({
          agent_id: "agent-finance-01",
          tool_id: testToolId,
          action: testAction,
          target: testTarget,
          payload: testPayload
        })
      });
      setProxyOutput(res);
    } catch (err) {
      alert("Proxy execution failed: " + (err instanceof Error ? err.message : "Error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">INTEGRATION GATEWAY</div>
          <h1>Secret-Aware Tool Proxy (Feature AB & F)</h1>
          <p>Route all tool and external API calls through a zero-trust proxy. Injects scoped credentials at egress, redacts sensitive request/response payloads, and enforces destination allowlists.</p>
        </div>
      </div>

      <div className="two-col">
        {/* Tool Inventory */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Registered Instrumented Tools</h2>
              <p>Managed API boundaries</p>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>TOOL ID</th>
                  <th>NAME</th>
                  <th>CATEGORY</th>
                  <th>RISK</th>
                  <th>ALLOWED DESTINATIONS</th>
                </tr>
              </thead>
              <tbody>
                {tools.map(t => (
                  <tr key={t.id}>
                    <td><code>{t.id}</code></td>
                    <td><strong>{t.name}</strong></td>
                    <td><span className="code-tag">{t.category}</span></td>
                    <td><span className={`badge ${t.risk_level.toLowerCase()}`}>{t.risk_level}</span></td>
                    <td>
                      <div className="tool-tags">
                        {t.allowed_destinations.map(d => <span key={d}>{d}</span>)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Test Proxy Gateway */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Proxy Ingress / Egress Gateway Tester</h2>
              <p>Simulate controlled outbound execution with credential injection</p>
            </div>
          </div>
          <div className="stack-form">
            <label>
              Select Tool
              <select value={testToolId} onChange={e => setTestToolId(e.target.value)}>
                {tools.map(t => <option key={t.id} value={t.id}>{t.name} ({t.id})</option>)}
              </select>
            </label>
            <label>
              Target Endpoint
              <input value={testTarget} onChange={e => setTestTarget(e.target.value)} />
            </label>
            <label>
              Payload
              <textarea rows={3} value={testPayload} onChange={e => setTestPayload(e.target.value)} />
            </label>
            <button className="primary-button" onClick={handleExecuteProxy} disabled={busy}>
              <Send size={15} /> Execute Through Proxy
            </button>
          </div>

          {proxyOutput && (
            <div className="result-body">
              <div className={`decision-card ${proxyOutput.proxy_result?.status === "SUCCESS" ? "allow" : "block"}`}>
                <strong>Status: {proxyOutput.proxy_result?.status}</strong>
                <small>Latency: {proxyOutput.proxy_result?.latency_ms}ms · Egress: {proxyOutput.proxy_result?.egress_allowed ? "ALLOWED" : "DENIED"}</small>
              </div>
              <h3>Proxy Headers & Sanitized Traces</h3>
              <pre className="code-block-preview">{JSON.stringify(proxyOutput.proxy_result?.result || proxyOutput.proxy_result?.error, null, 2)}</pre>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
