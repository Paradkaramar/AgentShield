import React from "react";
import { RefreshCw, Bell, Search, ShieldCheck, Cpu } from "lucide-react";
import { User } from "../types";

interface Props {
  currentPage: string;
  onRefresh: () => void;
  pendingApprovals: number;
  currentUser: User | null;
  onOpenApprovals: () => void;
  onOpenJarvis: () => void;
}

export const Topbar: React.FC<Props> = ({
  currentPage,
  onRefresh,
  pendingApprovals,
  currentUser,
  onOpenApprovals,
  onOpenJarvis
}) => {
  return (
    <header className="topbar">
      <div className="breadcrumbs">
        <span>Control Plane</span>
        <span className="separator">/</span>
        <strong>{currentPage}</strong>
      </div>

      <div className="top-actions">
        <div className="env-pill">
          <span className="pulse" />
          <span>ZERO-TRUST ENFORCING</span>
        </div>

        <button
          className="jarvis-topbar-button"
          onClick={onOpenJarvis}
          title="Open JARVIS AI Assistant (Ctrl+J)"
          aria-label="Open JARVIS AI Assistant"
        >
          <span className="jarvis-topbar-pulse" />
          <Cpu size={15} />
          <span>JARVIS AI</span>
        </button>

        <button className="icon-button" onClick={onRefresh} title="Refresh System Telemetry">
          <RefreshCw size={16} />
        </button>

        <button
          className="icon-button notification"
          onClick={onOpenApprovals}
          title="Pending Approvals"
        >
          <Bell size={16} />
          {pendingApprovals > 0 && <i />}
        </button>

        <div className="user-profile-badge">
          <div className="avatar small-avatar">
            {currentUser?.username.substring(0, 2).toUpperCase() || "AS"}
          </div>
          <div className="user-profile-info">
            <strong>{currentUser?.full_name || "SecOps Analyst"}</strong>
            <small>{currentUser?.role?.toUpperCase() || "ADMIN"}</small>
          </div>
        </div>
      </div>
    </header>
  );
};
