import React, { useState, useEffect } from "react";
import { ShieldCheck, UploadCloud, RefreshCw, FileCode, CheckCircle2, AlertTriangle } from "lucide-react";
import { PolicyVersion } from "../types";
import { request } from "../api";

export const PolicyAsCodePage: React.FC = () => {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [yamlContent, setYamlContent] = useState(`version: "1.1.0"
metadata:
  name: "AgentShield Production Security Baseline"
  enforcement_mode: "STRICT_ZERO_TRUST"
rules:
  - id: "RULE-01"
    name: "Block External Exfiltration"
    action: "EXPORT"
    target: "external:*"
    effect: "BLOCK"
  - id: "RULE-02"
    name: "Require Approval for Deletes"
    action: "DELETE"
    target: "*"
    effect: "ASK_HUMAN"
  - id: "RULE-03"
    name: "Prevent Direct Shell Execution"
    action: "EXECUTE"
    target: "shell:*"
    effect: "BLOCK"
`);
  const [changeSummary, setChangeSummary] = useState("Updated external egress rules and added shell block");
  const [deployResult, setDeployResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function fetchVersions() {
    try {
      const data = await request<PolicyVersion[]>("/api/policies/versions");
      setVersions(data);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchVersions();
  }, []);

  async function handleDeploy(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await request<any>("/api/policies/deploy", {
        method: "POST",
        body: JSON.stringify({
          version: `v1.${versions.length + 1}.0`,
          policy_yaml: yamlContent,
          change_summary: changeSummary
        })
      });
      setDeployResult(res);
      fetchVersions();
    } catch (err) {
      alert("Deployment failed: " + (err instanceof Error ? err.message : "Error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">DECLARATIVE GOVERNANCE</div>
          <h1>Policy-as-Code & GitOps (Feature AH)</h1>
          <p>Manage agent security policies declaratively in version-controlled YAML. Validate schemas, inspect version diffs, and audit every release deployment.</p>
        </div>
      </div>

      <div className="two-col">
        {/* YAML Editor Panel */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Declarative Policy YAML Specification</h2>
              <p>GitOps declarative release editor</p>
            </div>
          </div>
          <form onSubmit={handleDeploy} className="stack-form">
            <label>
              Release Change Summary:
              <input value={changeSummary} onChange={e => setChangeSummary(e.target.value)} />
            </label>
            <label>
              Policy-as-Code YAML:
              <textarea
                rows={12}
                className="code-editor-font"
                value={yamlContent}
                onChange={e => setYamlContent(e.target.value)}
              />
            </label>
            <button type="submit" className="primary-button" disabled={busy}>
              <UploadCloud size={15} /> Validate & Deploy via GitOps
            </button>
          </form>

          {deployResult && (
            <div className="result-body">
              <div className="decision-card allow">
                <CheckCircle2 size={18} />
                <strong>{deployResult.message}</strong>
                <small>Rules verified: {deployResult.rule_count}</small>
              </div>
            </div>
          )}
        </section>

        {/* Versions History */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Deployment Version History ({versions.length})</h2>
              <p>Audit trail of deployed security policies</p>
            </div>
            <button className="icon-button" onClick={fetchVersions}><RefreshCw size={14}/></button>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>VERSION</th>
                  <th>AUTHOR</th>
                  <th>SUMMARY</th>
                  <th>STATUS</th>
                  <th>DEPLOYED AT</th>
                </tr>
              </thead>
              <tbody>
                {versions.map(v => (
                  <tr key={v.id}>
                    <td><code>{v.version}</code></td>
                    <td>{v.author}</td>
                    <td className="reason-cell">{v.change_summary}</td>
                    <td><span className="badge active">{v.status}</span></td>
                    <td>{new Date(v.created_at).toLocaleString()}</td>
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
