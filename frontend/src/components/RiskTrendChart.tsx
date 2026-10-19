import React from "react";

interface Props {
  points: Array<{ id: number; risk: number; trust: number; time: string }>;
  currentAvgRisk: number;
  currentAvgTrust: number;
}

export const RiskTrendChart: React.FC<Props> = ({ points, currentAvgRisk, currentAvgTrust }) => {
  const width = 680;
  const height = 180;
  const padding = 35;

  if (!points || points.length === 0) {
    return <div className="empty-inline">Insufficient historical event samples for risk trend plotting.</div>;
  }

  const minX = padding;
  const maxX = width - padding;
  const minY = padding;
  const maxY = height - padding;

  const getX = (i: number) => minX + (i / Math.max(1, points.length - 1)) * (maxX - minX);
  const getY = (val: number) => maxY - (val / 100) * (maxY - minY);

  const riskPath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${getX(i)} ${getY(p.risk)}`).join(" ");
  const trustPath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${getX(i)} ${getY(p.trust)}`).join(" ");

  return (
    <div className="risk-chart-wrap">
      <div className="chart-legend-row">
        <span className="legend-item"><span className="legend-dot danger"/> Dynamic Risk Score (Avg: {currentAvgRisk})</span>
        <span className="legend-item"><span className="legend-dot safe"/> Continuous Trust Score (Avg: {currentAvgTrust})</span>
      </div>
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} className="trend-svg">
        {/* Horizontal grid lines */}
        {[25, 50, 75, 100].map(val => (
          <g key={val}>
            <line x1={minX} y1={getY(val)} x2={maxX} y2={getY(val)} stroke="#1e2c41" strokeDasharray="3 3"/>
            <text x={minX - 8} y={getY(val) + 3} fill="#627794" fontSize="8" textAnchor="end">{val}</text>
          </g>
        ))}

        {/* Risk line (red/orange) */}
        <path d={riskPath} fill="none" stroke="#ff6b6b" strokeWidth="2.4" />
        {points.map((p, i) => (
          <circle key={`r-${i}`} cx={getX(i)} cy={getY(p.risk)} r="3" fill="#ff6b6b" />
        ))}

        {/* Trust line (green/teal) */}
        <path d={trustPath} fill="none" stroke="#42d69b" strokeWidth="2.2" strokeDasharray="3 2" />
        {points.map((p, i) => (
          <circle key={`t-${i}`} cx={getX(i)} cy={getY(p.trust)} r="3" fill="#42d69b" />
        ))}
      </svg>
    </div>
  );
};
