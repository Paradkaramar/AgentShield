import React from "react";
import { GraphNode, GraphEdge } from "../types";
import { ShieldCheck, ShieldAlert, Database, Server, Globe, Bot } from "lucide-react";

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const AttackGraphView: React.FC<Props> = ({ nodes, edges }) => {
  // Compute basic coordinates for a clean layered layout:
  // Layer 0: Agents (left)
  // Layer 1: Intermediate Tools/Gateways (middle)
  // Layer 2: Target Resources / External Destinations (right)
  
  const agentNodes = nodes.filter(n => n.type === "agent" || (!n.type && n.id.startsWith("agent-")));
  const resourceNodes = nodes.filter(n => n.type !== "agent" && !n.id.startsWith("agent-"));

  const width = 850;
  const height = Math.max(380, Math.max(agentNodes.length, resourceNodes.length) * 90);

  const nodePositions: Record<string, { x: number; y: number }> = {};

  agentNodes.forEach((node, i) => {
    nodePositions[node.id] = {
      x: 140,
      y: 70 + (i * ((height - 120) / Math.max(1, agentNodes.length - 1 || 1)))
    };
  });

  resourceNodes.forEach((node, i) => {
    nodePositions[node.id] = {
      x: 680,
      y: 70 + (i * ((height - 120) / Math.max(1, resourceNodes.length - 1 || 1)))
    };
  });

  return (
    <div className="graph-container">
      <div className="graph-header">
        <div className="graph-legend">
          <span className="legend-item"><span className="legend-dot agent"/> Agents</span>
          <span className="legend-item"><span className="legend-dot allowed"/> Policy Allowed</span>
          <span className="legend-item"><span className="legend-dot blocked"/> Intercepted / Blocked</span>
          <span className="legend-item"><span className="legend-dot resource"/> Target Resource</span>
        </div>
      </div>
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} className="attack-graph-svg">
        <defs>
          <marker id="arrow-allow" markerWidth="8" markerHeight="8" refX="28" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#42d69b" />
          </marker>
          <marker id="arrow-block" markerWidth="8" markerHeight="8" refX="28" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#ff6b6b" />
          </marker>
          <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Central Policy Enforcement Gateway Zone */}
        <rect x="360" y="30" width="130" height={height - 60} rx="12" fill="#121e33" stroke="#253a5c" strokeDasharray="4 4" opacity="0.8"/>
        <text x="425" y="55" fill="#789bc4" fontSize="10" fontWeight="700" textAnchor="middle" letterSpacing="0.8">POLICY GATEWAY</text>
        <line x1="425" y1="70" x2="425" y2={height - 50} stroke="#253a5c" strokeDasharray="2 4" />

        {/* Draw edges */}
        {edges.map((edge, i) => {
          const start = nodePositions[edge.source];
          const end = nodePositions[edge.target];
          if (!start || !end) return null;

          const midX = 425;
          const isBlocked = edge.is_blocked || edge.decision === "BLOCK";
          const pathD = `M ${start.x} ${start.y} C ${midX - 40} ${start.y}, ${midX + 40} ${end.y}, ${end.x} ${end.y}`;

          return (
            <g key={`edge-${i}`} className={`edge-group ${isBlocked ? "edge-blocked" : "edge-allowed"}`}>
              <path
                d={pathD}
                fill="none"
                stroke={isBlocked ? "#ff5252" : "#3ecf8e"}
                strokeWidth={isBlocked ? 2.5 : 1.8}
                strokeDasharray={isBlocked ? "6 4" : "none"}
                markerEnd={isBlocked ? "url(#arrow-block)" : "url(#arrow-allow)"}
                filter={isBlocked ? "url(#glow-red)" : "none"}
              />
              {/* Midpoint badge for action */}
              <rect
                x={midX - 35}
                y={((start.y + end.y) / 2) - 10}
                width="70"
                height="20"
                rx="5"
                fill={isBlocked ? "#3b1e25" : "#132b24"}
                stroke={isBlocked ? "#66303d" : "#245946"}
              />
              <text
                x={midX}
                y={((start.y + end.y) / 2) + 3}
                fill={isBlocked ? "#ff9797" : "#7de0b2"}
                fontSize="9"
                fontWeight="600"
                textAnchor="middle"
              >
                {edge.action || "INVOKE"}
              </text>
            </g>
          );
        })}

        {/* Draw nodes */}
        {nodes.map(node => {
          const pos = nodePositions[node.id];
          if (!pos) return null;
          const isAgent = node.type === "agent" || node.id.startsWith("agent-");

          return (
            <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} className="node-group">
              <circle
                r="24"
                fill={isAgent ? "#172b47" : "#1a2538"}
                stroke={isAgent ? (node.status === "ACTIVE" ? "#4f8cff" : "#ff5e57") : "#47618a"}
                strokeWidth="2.2"
              />
              <text y="4" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="700">
                {isAgent ? "AI" : "RES"}
              </text>
              <text
                y="38"
                textAnchor="middle"
                fill="#d2deef"
                fontSize="11"
                fontWeight="600"
                className="node-label"
              >
                {node.label}
              </text>
              <text
                y="50"
                textAnchor="middle"
                fill="#7086a4"
                fontSize="9"
              >
                {isAgent ? `Status: ${node.status || "ACTIVE"} · Risk: ${node.risk || 10}` : `Endpoint`}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
