import React, { useState, useEffect } from "react";
import { Network, RefreshCw, ShieldAlert, CheckCircle2 } from "lucide-react";
import { AttackGraphView } from "../components/AttackGraphView";
import { request } from "../api";

export const AttackGraphPage: React.FC = () => {
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);

  async function fetchGraph() {
    setLoading(true);
    try {
      const data = await request<any>("/api/analytics/attack-graph");
      setGraphData(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchGraph();
  }, []);

  return (
    <div className="page-wrapper">
      <div className="page-heading">
        <div>
          <div className="eyebrow">GRAPH RECONNAISSANCE</div>
          <h1>Agent Attack Graph Explorer (Feature O)</h1>
          <p>Interactive graph illustrating relationships between agents, invocations, Policy Gateways, and target destinations with earliest known intervention points.</p>
        </div>
        <button className="secondary-button" onClick={fetchGraph}>
          <RefreshCw size={15} /> Refresh Graph
        </button>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Attack Path & Policy Intervention Topology</h2>
            <p>Green: Verified Zero-Trust egress · Red: Gateway Interception Point</p>
          </div>
        </div>
        <div className="graph-wrapper-card">
          <AttackGraphView nodes={graphData.nodes} edges={graphData.edges} />
        </div>
      </section>
    </div>
  );
};
