import React, { useState, useEffect } from "react";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { OverviewPage } from "./pages/OverviewPage";
import { RealTimeMonitorPage } from "./pages/RealTimeMonitorPage";
import { AgentsPage } from "./pages/AgentsPage";
import { AgentLabPage } from "./pages/AgentLabPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { PromptInjectionPage } from "./pages/PromptInjectionPage";
import { DlpPage } from "./pages/DlpPage";
import { CanaryTokensPage } from "./pages/CanaryTokensPage";
import { ShadowAiPage } from "./pages/ShadowAiPage";
import { AttackGraphPage } from "./pages/AttackGraphPage";
import { DelegationGraphPage } from "./pages/DelegationGraphPage";
import { RedTeamPage } from "./pages/RedTeamPage";
import { PredictiveRiskPage } from "./pages/PredictiveRiskPage";
import { DigitalTwinPage } from "./pages/DigitalTwinPage";
import { ToolProxyPage } from "./pages/ToolProxyPage";
import { SecretManagerPage } from "./pages/SecretManagerPage";
import { BehaviorDriftPage } from "./pages/BehaviorDriftPage";
import { PolicyAsCodePage } from "./pages/PolicyAsCodePage";
import { ReverseEngineeringPage } from "./pages/ReverseEngineeringPage";
import { ForensicReportPage } from "./pages/ForensicReportPage";
import { AuditTrailPage } from "./pages/AuditTrailPage";
import { SettingsPage } from "./pages/SettingsPage";
import { LoginPage } from "./pages/LoginPage";
import { JarvisPage } from "./pages/JarvisPage";
import { JarvisModalDrawer } from "./components/jarvis/JarvisModalDrawer";
import { Cpu } from "lucide-react";
import { Agent, EventItem, Approval, SOC_Overview, User } from "./types";
import { request, getAuthToken, setAuthToken } from "./api";

export default function App() {
  const [currentPage, setCurrentPage] = useState("Overview");
  const [overview, setOverview] = useState<SOC_Overview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [isJarvisOpen, setIsJarvisOpen] = useState(false);

  // Global hotkey: Ctrl+J / Cmd+J toggles JARVIS AI Assistant
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "j") {
        e.preventDefault();
        setIsJarvisOpen(prev => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  async function refreshAll() {
    try {
      const [o, a, e, ap] = await Promise.all([
        request<SOC_Overview>("/api/overview"),
        request<Agent[]>("/api/agents"),
        request<EventItem[]>("/api/events?limit=25"),
        request<Approval[]>("/api/approvals")
      ]);
      setOverview(o);
      setAgents(a);
      setEvents(e);
      setApprovals(ap);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error connecting to AgentShield API");
    }
  }

  useEffect(() => {
    refreshAll();
    const interval = window.setInterval(refreshAll, 6000);
    return () => window.clearInterval(interval);
  }, []);

  async function handleKillAgent(agent: Agent) {
    if (!window.confirm(`Activate EMERGENCY KILL SWITCH for agent ${agent.name} (${agent.id})?`)) return;
    try {
      await request(`/api/agents/${agent.id}/kill`, { method: "POST" });
      setNotice(`EMERGENCY KILL SWITCH ACTIVATED: Agent ${agent.name} quarantined.`);
      refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Kill switch failed");
    }
  }

  async function handleReactivateAgent(agent: Agent) {
    try {
      await request(`/api/agents/${agent.id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status: "ACTIVE" })
      });
      setNotice(`Agent ${agent.name} reactivated.`);
      refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reactivation failed");
    }
  }

  const pendingApprovalsCount = approvals.filter(a => a.status === "PENDING").length;

  return (
    <div className="app-shell">
      <Sidebar
        currentPage={currentPage}
        onSelectPage={setCurrentPage}
        pendingApprovals={pendingApprovalsCount}
        openIncidents={overview?.open_incidents ?? 0}
        shadowAiCount={overview?.shadow_ai_count ?? 0}
      />

      <main className="main">
        <Topbar
          currentPage={currentPage}
          onRefresh={refreshAll}
          pendingApprovals={pendingApprovalsCount}
          currentUser={currentUser}
          onOpenApprovals={() => setCurrentPage("Approvals")}
          onOpenJarvis={() => setIsJarvisOpen(true)}
        />

        <div className="content">
          {error && (
            <div className="alert error">
              <span><strong>Connection error:</strong> {error}</span>
              <button onClick={() => setError("")}>×</button>
            </div>
          )}

          {notice && (
            <div className="alert success">
              <span>{notice}</span>
              <button onClick={() => setNotice("")}>×</button>
            </div>
          )}

          {currentPage === "Overview" && (
            <OverviewPage
              overview={overview}
              agents={agents}
              events={events}
              onSelectPage={setCurrentPage}
              onKillAgent={handleKillAgent}
              onRefresh={refreshAll}
            />
          )}

          {currentPage === "Real-Time Monitor" && <RealTimeMonitorPage />}

          {currentPage === "Agents" && (
            <AgentsPage
              agents={agents}
              onRefresh={refreshAll}
              onKillAgent={handleKillAgent}
              onReactivateAgent={handleReactivateAgent}
            />
          )}

          {currentPage === "Agent Lab" && (
            <AgentLabPage agents={agents} onRefresh={refreshAll} />
          )}

          {currentPage === "Approvals" && (
            <ApprovalsPage approvals={approvals} onRefresh={refreshAll} />
          )}

          {currentPage === "Incidents & Alerts" && <IncidentsPage />}

          {currentPage === "Prompt Injection" && <PromptInjectionPage />}

          {currentPage === "DLP Policy & Events" && <DlpPage />}

          {currentPage === "Canary Tokens" && <CanaryTokensPage />}

          {currentPage === "Shadow AI Discovery" && (
            <ShadowAiPage onRefreshAll={refreshAll} />
          )}

          {currentPage === "Attack Graph" && <AttackGraphPage />}

          {currentPage === "Delegation Graph" && <DelegationGraphPage />}

          {currentPage === "Red-Team Simulation" && (
            <RedTeamPage agents={agents} onRefreshAll={refreshAll} />
          )}

          {currentPage === "Predictive Risk" && (
            <PredictiveRiskPage agents={agents} />
          )}

          {currentPage === "Digital Twin Replay" && (
            <DigitalTwinPage agents={agents} />
          )}

          {currentPage === "Tool Proxy Gateway" && <ToolProxyPage />}

          {currentPage === "Secret Manager" && <SecretManagerPage />}

          {currentPage === "Behavioral Drift" && (
            <BehaviorDriftPage agents={agents} />
          )}

          {currentPage === "Policy-as-Code & GitOps" && <PolicyAsCodePage />}

          {currentPage === "Reverse Engineering" && (
            <ReverseEngineeringPage agents={agents} />
          )}

          {currentPage === "Forensic Dossiers" && <ForensicReportPage />}

          {currentPage === "JARVIS Assistant" && (
            <JarvisPage
              onNavigatePage={setCurrentPage}
              selectedAgentId={agents[0]?.id}
              selectedIncidentId={overview?.open_incidents ? 1 : undefined}
            />
          )}

          {currentPage === "Cryptographic Audit" && <AuditTrailPage />}

          {currentPage === "Settings & RBAC" && <SettingsPage />}

          {currentPage === "Login" && (
            <LoginPage
              onLoginSuccess={user => {
                setCurrentUser(user);
                setCurrentPage("Overview");
              }}
            />
          )}
        </div>
      </main>

      {/* Persistent Floating JARVIS HUD Launcher Button */}
      <button
        type="button"
        className={`jarvis-floating-launcher ${isJarvisOpen ? "active" : ""}`}
        onClick={() => setIsJarvisOpen(prev => !prev)}
        title="Toggle JARVIS AI Security Assistant (Ctrl+J)"
        aria-label="Toggle JARVIS AI Security Assistant"
      >
        <span className="launcher-pulse-ring" />
        <div className="launcher-core">
          <Cpu size={22} className="launcher-icon" />
        </div>
        <span className="launcher-label">JARVIS</span>
      </button>

      {/* Sliding HUD Modal Drawer */}
      <JarvisModalDrawer
        isOpen={isJarvisOpen}
        onClose={() => setIsJarvisOpen(false)}
        onNavigatePage={setCurrentPage}
        currentPage={currentPage}
        selectedAgentId={agents[0]?.id}
        selectedIncidentId={overview?.open_incidents ? 1 : undefined}
      />
    </div>
  );
}
