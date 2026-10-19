import React, { useState, useEffect } from "react";
import { GitFork, RefreshCw, AlertTriangle, ShieldCheck } from "lucide-react";
import { DelegationGraphView } from "../components/DelegationGraphView";
import { request } from "../api";

export const DelegationGraphPage: React.FC = () => {
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);

  async function fetchGraph() {
    setLoading(true);
    try {
      const data = await request<any>("/api/analytics/delegation-graph");
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
          <div className="eyebrow">AGENT-TO-AGENT SECURITY</div>
          <h1>Multi-Agent Delegation Mesh (Feature Z & P)</h1>
          <p>Inspect permitted inter-agent communication, cross-agent delegation chains, trust decay rates, and privilege boundary jumps.</p>
        </div>
        <button className="secondary-button" onClick={fetchGraph}>
          <RefreshCw size={15} /> Refresh Mesh
        </button>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Trust Boundary & Delegation Mesh Topology</h2>
            <p>15% linear trust decay per delegation hop</p>
          </div>
        </div>
        <div className="graph-wrapper-card">
          <DelegationGraphView nodes={graphData.nodes} edges={graphData.edges} />
        </div>
      </section>
    </div>
  );
};
