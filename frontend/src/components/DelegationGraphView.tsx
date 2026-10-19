import React from "react";
import { GraphNode, GraphEdge } from "../types";

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const DelegationGraphView: React.FC<Props> = ({ nodes, edges }) => {
  const width = 800;
  const height = 360;

  // Circular layout for multi-agent delegation mesh
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = 130;

  const positions: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n, idx) => {
    const angle = (idx / Math.max(1, nodes.length)) * 2 * Math.PI - Math.PI / 2;
    positions[n.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle)
    };
  });

  return (
    <div className="graph-container">
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <marker id="arrow-del" markerWidth="8" markerHeight="8" refX="26" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#7666ff" />
          </marker>
        </defs>

        {/* Central Trust Boundary Zone */}
        <circle cx={centerX} cy={centerY} r={radius + 40} fill="none" stroke="#253a5c" strokeDasharray="5 5" opacity="0.6"/>
        <text x={centerX} y={centerY - 5} fill="#627d9e" fontSize="10" textAnchor="middle" fontWeight="600">ZERO-TRUST DELEGATION BOUNDARY</text>
        <text x={centerX} y={centerY + 12} fill="#4f6888" fontSize="8" textAnchor="middle">15% Trust Decay per Hop</text>

        {/* Edges */}
        {edges.map((e, idx) => {
          const start = positions[e.source];
          const end = positions[e.target];
          if (!start || !end) return null;

          return (
            <g key={`del-edge-${idx}`}>
              <line
                x1={start.x}
                y1={start.y}
                x2={end.x}
                y2={end.y}
                stroke="#8b7aff"
                strokeWidth="2"
                strokeDasharray="4 2"
                markerEnd="url(#arrow-del)"
              />
              <rect
                x={(start.x + end.x) / 2 - 25}
                y={(start.y + end.y) / 2 - 8}
                width="50"
                height="16"
                rx="4"
                fill="#191d33"
                stroke="#373468"
              />
              <text
                x={(start.x + end.x) / 2}
                y={(start.y + end.y) / 2 + 4}
                fill="#b6abff"
                fontSize="8"
                fontWeight="700"
                textAnchor="middle"
              >
                -15% HOP
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const pos = positions[node.id];
          if (!pos) return null;

          return (
            <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`}>
              <circle r="26" fill="#1b253d" stroke="#5d72f5" strokeWidth="2.5" />
              <text y="4" textAnchor="middle" fill="#ffffff" fontSize="10" fontWeight="700">
                {node.trust ?? 90}
              </text>
              <text y="38" textAnchor="middle" fill="#dbe6f6" fontSize="10" fontWeight="600">
                {node.label}
              </text>
              <text y="49" textAnchor="middle" fill="#7186a2" fontSize="8">
                Trust: {node.trust ?? 90}/100
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
