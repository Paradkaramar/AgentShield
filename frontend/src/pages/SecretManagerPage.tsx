import React, { useState } from "react";
import { KeyRound, ShieldCheck, Eye, EyeOff, Lock, CheckCircle2 } from "lucide-react";

export const SecretManagerPage: React.FC = () => {
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});

  const secrets = [
    { key: "OPENAI_API_KEY", scope: "openai.com", value: "sk-proj-demo-mock-key-shield-vaulted-9941", status: "VAULTED_SCOPED", last_rotated: "2026-10-15" },
    { key: "ANTHROPIC_API_KEY", scope: "anthropic.com", value: "sk-ant-demo-mock-key-shield-vaulted-3829", status: "VAULTED_SCOPED", last_rotated: "2026-10-14" },
    { key: "DB_PROD_PASSWORD", scope: "postgres-internal.lan", value: "vaulted_db_pass_redacted_for_security", status: "ENCLAVE_ISOLATED", last_rotated: "2026-10-10" },
    { key: "SLACK_WEBHOOK_URL", scope: "hooks.slack.com", value: "https://hooks.slack.com/services/T00/B00/X00MOCK", status: "INTEGRATION_KEY", last_rotated: "2026-10-01" },
  ];

  function toggleReveal(key: string) {
    setRevealed(prev => ({ ...prev, [key]: !prev[key] }));
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">CREDENTIAL PROTECTION</div>
          <h1>Secret Manager & Enclave Vault (Feature I)</h1>
          <p>Prevent raw secret leaks, store scoped third-party credentials securely, and automatically scrub secrets from logs and agent contexts.</p>
        </div>
      </div>

      <div className="banner cyber-banner">
        <div className="banner-icon"><Lock size={22} /></div>
        <div className="banner-copy">
          <strong>Automatic Credential Redaction Active</strong>
          <p>Any OpenAI keys (`sk-...`), AWS Access Keys (`AKIA...`), JWT tokens, or passwords detected in outbound agent telemetry are automatically scrubbed by the DLP engine before storage.</p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Managed Secret Vault Credentials</h2>
            <p>Stored in simulated hardware enclave</p>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>SECRET IDENTIFIER</th>
                <th>EGRESS SCOPE</th>
                <th>ENCLAVE VALUE</th>
                <th>ENCRYPTION STATUS</th>
                <th>LAST ROTATED</th>
                <th>REDACTION</th>
              </tr>
            </thead>
            <tbody>
              {secrets.map(s => {
                const isShown = revealed[s.key];
                return (
                  <tr key={s.key}>
                    <td><strong>{s.key}</strong></td>
                    <td><span className="code-tag">{s.scope}</span></td>
                    <td>
                      <code>
                        {isShown ? s.value : "••••••••••••••••••••••••••••••••"}
                      </code>
                    </td>
                    <td><span className="badge active">{s.status}</span></td>
                    <td>{s.last_rotated}</td>
                    <td>
                      <button className="secondary-button small-btn" onClick={() => toggleReveal(s.key)}>
                        {isShown ? <EyeOff size={13} /> : <Eye size={13} />} {isShown ? "Hide" : "Reveal"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
