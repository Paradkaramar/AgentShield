import React, { useState, useEffect } from "react";
import { Settings as SettingsIcon, Users, Shield, Plus, Lock, CheckCircle2 } from "lucide-react";
import { User } from "../types";
import { request } from "../api";

export const SettingsPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [showNewUser, setShowNewUser] = useState(false);
  const [userForm, setUserForm] = useState({
    username: "",
    password: "",
    role: "security_analyst",
    full_name: "",
    email: ""
  });
  const [busy, setBusy] = useState(false);

  async function fetchUsers() {
    try {
      const data = await request<User[]>("/api/auth/users");
      setUsers(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchUsers();
  }, []);

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await request("/api/auth/register", {
        method: "POST",
        body: JSON.stringify(userForm)
      });
      setShowNewUser(false);
      setUserForm({ username: "", password: "", role: "security_analyst", full_name: "", email: "" });
      fetchUsers();
    } catch (err) {
      alert("Failed to create user: " + (err instanceof Error ? err.message : "Error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">GOVERNANCE & PLATFORM SETTINGS</div>
          <h1>Organization, Users & RBAC Roles (Page 25)</h1>
          <p>Configure Role-Based Access Control, tenant boundaries, user accounts, and Zero-Trust enforcement parameters.</p>
        </div>
        <button className="primary-button" onClick={() => setShowNewUser(true)}>
          <Plus size={15} /> Add User
        </button>
      </div>

      {showNewUser && (
        <section className="panel form-panel">
          <div className="panel-heading">
            <div>
              <h2>Create SOC Operator / Analyst Account</h2>
              <p>Assign explicit role and credentials</p>
            </div>
            <button className="icon-button" onClick={() => setShowNewUser(false)}>×</button>
          </div>
          <form onSubmit={handleCreateUser} className="form-grid">
            <label>
              Username
              <input required value={userForm.username} onChange={e => setUserForm({ ...userForm, username: e.target.value })} />
            </label>
            <label>
              Password
              <input type="password" required value={userForm.password} onChange={e => setUserForm({ ...userForm, password: e.target.value })} />
            </label>
            <label>
              Full Name
              <input required value={userForm.full_name} onChange={e => setUserForm({ ...userForm, full_name: e.target.value })} />
            </label>
            <label>
              Email Address
              <input type="email" required value={userForm.email} onChange={e => setUserForm({ ...userForm, email: e.target.value })} />
            </label>
            <label className="wide">
              Assigned Role
              <select value={userForm.role} onChange={e => setUserForm({ ...userForm, role: e.target.value })}>
                <option value="admin">Chief Administrator (Full Access)</option>
                <option value="security_analyst">Security Analyst (Triage & Approvals)</option>
                <option value="operator">Operator (Agent Lifecycle & Testing)</option>
                <option value="auditor">Auditor (Read-Only Compliance & Integrity)</option>
              </select>
            </label>
            <div className="wide form-actions">
              <button type="submit" className="primary-button" disabled={busy}>Confirm Account Creation</button>
            </div>
          </form>
        </section>
      )}

      <div className="two-col">
        {/* Users Table */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Registered SOC Users ({users.length})</h2>
              <p>Role-Based Access Control (RBAC)</p>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>USERNAME</th>
                  <th>FULL NAME</th>
                  <th>ROLE</th>
                  <th>EMAIL</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td><strong>{u.username}</strong></td>
                    <td>{u.full_name}</td>
                    <td><span className="code-tag">{u.role}</span></td>
                    <td>{u.email}</td>
                    <td><span className="badge active">ACTIVE</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Global Security Settings */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Control Plane Enforcement Settings</h2>
              <p>Zero-Trust configuration</p>
            </div>
          </div>
          <div className="result-body">
            <div className="stat-pill full-pill">
              Default Egress Policy: <strong>DENY ALL (Least Privilege)</strong>
            </div>
            <div className="stat-pill full-pill">
              Cryptographic Hash Ledger: <strong>SHA-256 Chained Integrity</strong>
            </div>
            <div className="stat-pill full-pill">
              Prompt Injection Detector: <strong>Heuristic + Base64 Normalized Scanning</strong>
            </div>
            <div className="stat-pill full-pill">
              Tool Proxy Enforcement: <strong>Strict Egress Allowlist + Vault Redaction</strong>
            </div>
            <div className="stat-pill full-pill">
              Continuous Trust Decay: <strong>15% per Delegation Hop</strong>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
