import React, { useState, useEffect } from "react";
import { Crosshair, Plus, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";
import { CanaryToken } from "../types";
import { request } from "../api";

export const CanaryTokensPage: React.FC = () => {
  const [canaries, setCanaries] = useState<CanaryToken[]>([]);
  const [tokenType, setTokenType] = useState("AWS_KEY");
  const [locationTag, setLocationTag] = useState("prod_env_shadow_var");
  const [busy, setBusy] = useState(false);

  async function fetchCanaries() {
    try {
      const data = await request<CanaryToken[]>("/api/canaries");
      setCanaries(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchCanaries();
  }, []);

  async function handleCreateCanary(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await request("/api/canaries", {
        method: "POST",
        body: JSON.stringify({ token_type: tokenType, location_tag: locationTag })
      });
      fetchCanaries();
      setLocationTag("custom_location_" + Math.floor(Math.random() * 1000));
    } catch (err) {
      alert("Failed to deploy canary");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">BREACH DETECTION TRIPWIRES</div>
          <h1>Canary Tokens & Honey Tokens (Feature AG)</h1>
          <p>Deploy synthetic credentials, API keys, and fake customer records. Any unauthorized agent access or exfiltration immediately trips a critical SOC incident.</p>
        </div>
      </div>

      <div className="two-col">
        {/* Create Canary Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Deploy Synthetic Honeytoken</h2>
              <p>Generate high-entropy unique canary identifiers</p>
            </div>
          </div>
          <form onSubmit={handleCreateCanary} className="stack-form">
            <label>
              Honeytoken Category
              <select value={tokenType} onChange={e => setTokenType(e.target.value)}>
                <option value="AWS_KEY">AWS Cloud Access Key (AKIA...)</option>
                <option value="OPENAI_KEY">OpenAI Secret API Key (sk-...)</option>
                <option value="DATABASE_CONN">PostgreSQL Connection String</option>
                <option value="CUSTOMER_SSN">Synthetic VIP Customer SSN</option>
              </select>
            </label>
            <label>
              Deployment Location / Tag
              <input value={locationTag} onChange={e => setLocationTag(e.target.value)} placeholder="e.g. mock_finance_table or fake_env_var" />
            </label>
            <button type="submit" className="primary-button" disabled={busy}>
              <Plus size={15} /> Deploy Honeytoken Tripwire
            </button>
          </form>
        </section>

        {/* Canary Tokens Table */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Active Canary Tokens ({canaries.length})</h2>
              <p>Tripwire surveillance ledger</p>
            </div>
            <button className="icon-button" onClick={fetchCanaries}><RefreshCw size={14}/></button>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>TYPE</th>
                  <th>TOKEN SIGNATURE</th>
                  <th>LOCATION</th>
                  <th>TRIPWIRE STATUS</th>
                </tr>
              </thead>
              <tbody>
                {canaries.map(c => (
                  <tr key={c.id}>
                    <td><span className="code-tag">{c.token_type}</span></td>
                    <td><code>{c.token_value}</code></td>
                    <td>{c.location_tag}</td>
                    <td>
                      {c.triggered ? (
                        <span className="badge danger">TRIPPED</span>
                      ) : (
                        <span className="badge active">ARMED</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
};
