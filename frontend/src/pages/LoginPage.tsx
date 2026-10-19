import React, { useState } from "react";
import { ShieldCheck, Lock, User as UserIcon, ArrowRight, KeyRound } from "lucide-react";
import { request, setAuthToken } from "../api";

interface Props {
  onLoginSuccess: (user: any) => void;
}

export const LoginPage: React.FC<Props> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("AgentShield#2026");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await request<any>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      setAuthToken(res.access_token);
      onLoginSuccess(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  function fillDemo(u: string, p: string) {
    setUsername(u);
    setPassword(p);
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-mark large">
            <ShieldCheck size={32} />
          </div>
          <h1>AgentShield</h1>
          <p className="login-tagline">"Who Controls the AI?"</p>
          <small className="subtext">Zero-Trust Security Control Plane for Autonomous Agents</small>
        </div>

        {error && <div className="alert error">{error}</div>}

        <form onSubmit={handleSubmit} className="stack-form">
          <label>
            Username
            <div className="input-with-icon">
              <UserIcon size={16} />
              <input required value={username} onChange={e => setUsername(e.target.value)} />
            </div>
          </label>
          <label>
            Password
            <div className="input-with-icon">
              <Lock size={16} />
              <input type="password" required value={password} onChange={e => setPassword(e.target.value)} />
            </div>
          </label>
          <button type="submit" className="primary-button full-button" disabled={busy}>
            {busy ? "Authenticating..." : "Access Control Plane"} <ArrowRight size={15} />
          </button>
        </form>

        <div className="demo-credentials-box">
          <small>DEMO CREDENTIALS QUICK-FILL:</small>
          <div className="demo-buttons-row">
            <button type="button" className="text-button" onClick={() => fillDemo("admin", "AgentShield#2026")}>
              Admin (AgentShield#2026)
            </button>
            <button type="button" className="text-button" onClick={() => fillDemo("analyst", "Analyst#2026")}>
              Analyst (Analyst#2026)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
