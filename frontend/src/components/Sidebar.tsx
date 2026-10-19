import React from "react";
import {
  ShieldCheck, LayoutDashboard, Radio, Bot, CheckCircle2,
  AlertTriangle, Eye, Lock, Crosshair, Network, GitFork,
  Cpu, FileCode, History, Database, FileText, KeyRound,
  TrendingUp, Activity, Terminal, Settings as SettingsIcon,
  Compass, Zap
} from "lucide-react";

interface Props {
  currentPage: string;
  onSelectPage: (page: string) => void;
  pendingApprovals: number;
  openIncidents: number;
  shadowAiCount: number;
}

export const Sidebar: React.FC<Props> = ({
  currentPage,
  onSelectPage,
  pendingApprovals,
  openIncidents,
  shadowAiCount
}) => {
  const sections = [
    {
      title: "CONTROL PLANE",
      items: [
        { name: "Overview", icon: LayoutDashboard },
        { name: "JARVIS Assistant", icon: Cpu, isJarvis: true },
        { name: "Real-Time Monitor", icon: Activity },
        { name: "Agents", icon: Bot },
        { name: "Agent Lab", icon: Radio },
        { name: "Approvals", icon: CheckCircle2, count: pendingApprovals },
      ]
    },
    {
      title: "THREAT DETECTION & DLP",
      items: [
        { name: "Incidents & Alerts", icon: AlertTriangle, count: openIncidents },
        { name: "Prompt Injection", icon: Eye },
        { name: "DLP Policy & Events", icon: Lock },
        { name: "Canary Tokens", icon: Crosshair },
        { name: "Shadow AI Discovery", icon: Compass, count: shadowAiCount },
      ]
    },
    {
      title: "ADVANCED ENGINES",
      items: [
        { name: "Attack Graph", icon: Network },
        { name: "Delegation Graph", icon: GitFork },
        { name: "Red-Team Simulation", icon: Zap },
        { name: "Predictive Risk", icon: TrendingUp },
        { name: "Digital Twin Replay", icon: Cpu },
        { name: "Tool Proxy Gateway", icon: Terminal },
      ]
    },
    {
      title: "REVERSE ENGINEERING",
      items: [
        { name: "Reverse Engineering", icon: FileCode },
        { name: "Forensic Dossiers", icon: FileText },
      ]
    },
    {
      title: "GOVERNANCE & ADMIN",
      items: [
        { name: "Policy-as-Code & GitOps", icon: ShieldCheck },
        { name: "Cryptographic Audit", icon: History },
        { name: "Secret Manager", icon: KeyRound },
        { name: "Behavioral Drift", icon: Activity },
        { name: "Settings & RBAC", icon: SettingsIcon },
      ]
    }
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <ShieldCheck size={22} />
        </div>
        <div>
          <strong>AgentShield</strong>
          <small className="tagline">"Who Controls the AI?"</small>
        </div>
      </div>

      <div className="workspace">
        <div className="workspace-dot" />
        <span>Enterprise SOC Control Plane</span>
      </div>

      <div className="nav-scroll-container">
        {sections.map(sec => (
          <div key={sec.title} className="nav-group">
            <div className="nav-label">{sec.title}</div>
            <nav>
              {sec.items.map(item => {
                const isActive = currentPage === item.name;
                const Icon = item.icon;
                return (
                  <button
                    key={item.name}
                    className={`nav-item ${isActive ? "active" : ""}`}
                    onClick={() => onSelectPage(item.name)}
                  >
                    <Icon size={16} />
                    <span>{item.name}</span>
                    {(item as any).isJarvis && (
                      <span className="jarvis-nav-badge">AI HUD</span>
                    )}
                    {item.count !== undefined && item.count > 0 && (
                      <em className="nav-counter">{item.count}</em>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      <div className="sidebar-bottom">
        <div className="status-card">
          <span className="pulse" />
          <span>Zero-Trust: <strong>Enforcing</strong></span>
        </div>
      </div>
    </aside>
  );
};
