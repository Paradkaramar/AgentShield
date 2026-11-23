import React, { useRef, useEffect, useState, useMemo, useCallback } from "react";
import Globe, { GlobeMethods } from "react-globe.gl";
import { GlobeNode, GlobeArc } from "../types";
import {
  Shield, AlertTriangle, CheckCircle, Wifi, Laptop, Server, Radio,
  ZoomIn, ZoomOut, RotateCcw, Play, Pause, Layers, Sparkles, Sliders
} from "lucide-react";

interface Props {
  globeNodes: GlobeNode[];
  virtualLanNodes: GlobeNode[];
  connectionArcs: GlobeArc[];
  selectedNode: GlobeNode | null;
  onSelectNode: (node: GlobeNode) => void;
  autoRotate: boolean;
  onToggleAutoRotate: () => void;
  viewMode: "3d" | "lan" | "split";
}

// Available High-Resolution, Properly Licensed Earth Textures
export type EarthTextureStyle = "realistic-nightlights" | "blue-marble" | "night-lights" | "dark-cyber";

const TEXTURE_OPTIONS: Record<EarthTextureStyle, { name: string; url: string; bumpUrl?: string }> = {
  "realistic-nightlights": {
    name: "Realistic Earth + City Lights",
    url: "/textures/earth-realistic-nightlights.jpg",
    bumpUrl: "/textures/earth-topology.png"
  },
  "blue-marble": {
    name: "NASA Blue Marble (Day)",
    url: "/textures/earth-blue-marble.jpg",
    bumpUrl: "/textures/earth-topology.png"
  },
  "night-lights": {
    name: "Global City Lights (Night)",
    url: "/textures/earth-night.jpg",
    bumpUrl: "/textures/earth-topology.png"
  },
  "dark-cyber": {
    name: "Tactical Carbon Cyber",
    url: "/textures/earth-dark.jpg",
    bumpUrl: "/textures/earth-topology.png"
  }
};

// Procedural fallback canvas texture if WebGL or remote image assets fail
function createCyberEarthFallbackTexture(): string {
  const canvas = document.createElement("canvas");
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext("2d");
  if (!ctx) return "";

  ctx.fillStyle = "#030604";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.strokeStyle = "rgba(0, 240, 255, 0.15)";
  ctx.lineWidth = 1;

  for (let lat = 0; lat <= canvas.height; lat += 32) {
    ctx.beginPath();
    ctx.moveTo(0, lat);
    ctx.lineTo(canvas.width, lat);
    ctx.stroke();
  }
  for (let lng = 0; lng <= canvas.width; lng += 32) {
    ctx.beginPath();
    ctx.moveTo(lng, 0);
    ctx.lineTo(lng, canvas.height);
    ctx.stroke();
  }

  // Tactical Continents
  ctx.fillStyle = "rgba(11, 24, 14, 0.92)";
  ctx.strokeStyle = "rgba(0, 240, 255, 0.35)";
  ctx.lineWidth = 1.5;

  ctx.beginPath();
  ctx.ellipse(250, 150, 110, 70, -0.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.ellipse(320, 320, 60, 90, 0.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.ellipse(520, 140, 50, 45, 0.1, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.ellipse(530, 260, 70, 95, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.ellipse(720, 160, 140, 85, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  ctx.beginPath();
  ctx.ellipse(820, 350, 60, 45, -0.1, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();

  return canvas.toDataURL("image/png");
}

export const CyberGlobeView: React.FC<Props> = ({
  globeNodes,
  virtualLanNodes,
  connectionArcs,
  selectedNode,
  onSelectNode,
  autoRotate,
  onToggleAutoRotate,
  viewMode
}) => {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [textureStyle, setTextureStyle] = useState<EarthTextureStyle>("realistic-nightlights");
  const [rotationSpeed, setRotationSpeed] = useState<number>(0.6);
  const [textureLoaded, setTextureLoaded] = useState<boolean>(false);
  const [textureError, setTextureError] = useState<boolean>(false);
  const [fallbackTexture, setFallbackTexture] = useState<string>("");
  const [showStyleMenu, setShowStyleMenu] = useState<boolean>(false);

  // Interaction tracking for automatic rotation resumption
  const userInteractingRef = useRef<boolean>(false);
  const resumeTimeoutRef = useRef<number | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const lastTimeRef = useRef<number>(performance.now());

  // Generate fallback texture in memory
  useEffect(() => {
    setFallbackTexture(createCyberEarthFallbackTexture());
  }, []);

  // Pre-load current Earth texture asset
  useEffect(() => {
    setTextureLoaded(false);
    setTextureError(false);
    const img = new Image();
    img.src = TEXTURE_OPTIONS[textureStyle].url;
    img.onload = () => {
      setTextureLoaded(true);
    };
    img.onerror = () => {
      console.warn(`Failed to load texture ${TEXTURE_OPTIONS[textureStyle].url}, falling back.`);
      setTextureError(true);
      setTextureLoaded(true);
    };
  }, [textureStyle]);

  // Handle responsive viewport sizing
  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        setDimensions({
          width: clientWidth || 800,
          height: clientHeight || 600
        });
      }
    };
    updateSize();
    window.addEventListener("resize", updateSize);

    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined" && containerRef.current) {
      ro = new ResizeObserver(() => {
        updateSize();
      });
      ro.observe(containerRef.current);
    }

    return () => {
      window.removeEventListener("resize", updateSize);
      if (ro) ro.disconnect();
    };
  }, []);


  // Configure OrbitControls for continuous, smooth rotation and auto-resume
  useEffect(() => {
    if (!globeRef.current) return;
    const controls = globeRef.current.controls();
    if (!controls) return;

    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = rotationSpeed;
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.rotateSpeed = 0.8;
    controls.zoomSpeed = 1.0;
    controls.enablePan = false;

    // Detect user interactions: pause auto-rotate while dragging/zooming
    const handleStart = () => {
      userInteractingRef.current = true;
      if (resumeTimeoutRef.current) {
        window.clearTimeout(resumeTimeoutRef.current);
      }
    };

    // When interaction ends (mouse release / touch release), resume slow rotation after 1.5s
    const handleEnd = () => {
      userInteractingRef.current = false;
      if (resumeTimeoutRef.current) {
        window.clearTimeout(resumeTimeoutRef.current);
      }
      if (autoRotate) {
        resumeTimeoutRef.current = window.setTimeout(() => {
          if (!userInteractingRef.current && globeRef.current) {
            const ctrl = globeRef.current.controls();
            if (ctrl) {
              ctrl.autoRotate = true;
              ctrl.autoRotateSpeed = rotationSpeed;
            }
          }
        }, 1500);
      }
    };

    controls.addEventListener("start", handleStart);
    controls.addEventListener("end", handleEnd);

    return () => {
      controls.removeEventListener("start", handleStart);
      controls.removeEventListener("end", handleEnd);
      if (resumeTimeoutRef.current) {
        window.clearTimeout(resumeTimeoutRef.current);
      }
    };
  }, [autoRotate, rotationSpeed]);

  // Delta-time continuous rotation animation loop
  useEffect(() => {
    lastTimeRef.current = performance.now();

    const loop = (now: number) => {
      const delta = (now - lastTimeRef.current) / 1000;
      lastTimeRef.current = now;

      if (globeRef.current) {
        const controls = globeRef.current.controls();
        if (controls) {
          // If autoRotate should be active and user is not currently dragging, ensure active
          if (autoRotate && !userInteractingRef.current && !controls.autoRotate) {
            controls.autoRotate = true;
          }
          // OrbitControls update with delta scaling
          controls.update();
        }
      }

      animFrameRef.current = requestAnimationFrame(loop);
    };

    animFrameRef.current = requestAnimationFrame(loop);

    return () => {
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
    };
  }, [autoRotate]);

  // Point camera to selected node if geolocated
  useEffect(() => {
    if (selectedNode && selectedNode.geolocated && selectedNode.latitude && selectedNode.longitude && globeRef.current) {
      globeRef.current.pointOfView(
        {
          lat: selectedNode.latitude,
          lng: selectedNode.longitude,
          altitude: 1.8
        },
        1200
      );
    }
  }, [selectedNode]);

  // Pulsing sonar beacon rings for alert nodes, verified assets, or selected nodes
  const ringsData = useMemo(() => {
    const rings: any[] = [];
    globeNodes.forEach(node => {
      if (node.geolocated && node.latitude && node.longitude) {
        if (node.indicator === "ALERT_CRITICAL") {
          rings.push({
            lat: node.latitude,
            lng: node.longitude,
            color: "#ef4444",
            maxR: 9,
            propagationSpeed: 2.8,
            repeatPeriod: 700
          });
        } else if (node.indicator === "ALERT_WARNING") {
          rings.push({
            lat: node.latitude,
            lng: node.longitude,
            color: "#f59e0b",
            maxR: 6,
            propagationSpeed: 2.0,
            repeatPeriod: 900
          });
        } else if (selectedNode && selectedNode.id === node.id) {
          rings.push({
            lat: node.latitude,
            lng: node.longitude,
            color: "#00f0ff",
            maxR: 7,
            propagationSpeed: 2.2,
            repeatPeriod: 800
          });
        } else {
          // Small continuous cyan pulse on verified online infrastructure nodes
          rings.push({
            lat: node.latitude,
            lng: node.longitude,
            color: "#00f0ff",
            maxR: 4,
            propagationSpeed: 1.5,
            repeatPeriod: 1400
          });
        }
      }
    });
    return rings;
  }, [globeNodes, selectedNode]);

  // Camera zoom and perspective handlers
  const handleZoomIn = () => {
    if (globeRef.current) {
      const pov = globeRef.current.pointOfView();
      globeRef.current.pointOfView({ ...pov, altitude: Math.max(0.5, pov.altitude * 0.75) }, 400);
    }
  };

  const handleZoomOut = () => {
    if (globeRef.current) {
      const pov = globeRef.current.pointOfView();
      globeRef.current.pointOfView({ ...pov, altitude: Math.min(3.8, pov.altitude * 1.3) }, 400);
    }
  };

  const handleResetCamera = () => {
    if (globeRef.current) {
      globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2.2 }, 800);
    }
  };

  const currentTextureUrl = textureError || !textureLoaded
    ? fallbackTexture
    : TEXTURE_OPTIONS[textureStyle].url;

  return (
    <div className="cyber-globe-viewport" ref={containerRef}>
      {/* 3D WebGL Globe View */}
      {(viewMode === "3d" || viewMode === "split") && (
        <div className={`globe-render-layer ${viewMode === "split" ? "split-left" : "full"}`}>
          {/* Subtle loading state indicator */}
          {!textureLoaded && (
            <div className="globe-texture-loading-indicator">
              <span className="spinner-mini" />
              <span>INITIALIZING 3D PLANETARY ENGINE...</span>
            </div>
          )}

          {currentTextureUrl && (
            <Globe
              ref={globeRef}
              width={viewMode === "split" ? dimensions.width * 0.58 : dimensions.width}
              height={dimensions.height}
              // Realistic Textured Earth & Space Background
              globeImageUrl={currentTextureUrl}
              bumpImageUrl={TEXTURE_OPTIONS[textureStyle].bumpUrl || "/textures/earth-topology.png"}
              backgroundImageUrl="/textures/night-sky.png"
              backgroundColor="rgba(3, 6, 4, 0)"
              // Glowing Atmospheric Halo
              showAtmosphere={true}
              atmosphereColor="#00f0ff"
              atmosphereAltitude={0.22}
              // Discovered Public Network Nodes
              pointsData={globeNodes.filter(n => n.geolocated && n.latitude !== null && n.longitude !== null)}
              pointLat="latitude"
              pointLng="longitude"
              pointColor={(d: any) =>
                d.indicator === "ALERT_CRITICAL"
                  ? "#ef4444"
                  : d.indicator === "ALERT_WARNING"
                  ? "#f59e0b"
                  : d.id === selectedNode?.id
                  ? "#00ff88"
                  : "#00f0ff"
              }
              pointAltitude={(d: any) =>
                d.indicator === "ALERT_CRITICAL" ? 0.08 : d.id === selectedNode?.id ? 0.1 : 0.04
              }
              pointRadius={(d: any) =>
                d.indicator === "ALERT_CRITICAL" ? 0.9 : d.id === selectedNode?.id ? 1.0 : 0.65
              }
              pointResolution={32}
              onPointClick={(point: any) => onSelectNode(point as GlobeNode)}
              pointLabel={(d: any) => `
                <div style="
                  background: rgba(8, 16, 11, 0.96);
                  border: 1px solid ${d.marker_color || '#00f0ff'};
                  box-shadow: 0 0 20px rgba(0, 240, 255, 0.35);
                  padding: 10px 14px;
                  border-radius: 8px;
                  font-family: monospace;
                  font-size: 11px;
                  color: #e2e8f0;
                  backdrop-filter: blur(12px);
                  pointer-events: none;
                  min-width: 200px;
                ">
                  <div style="font-weight: 800; color: ${d.marker_color || '#00f0ff'}; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                    <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${d.marker_color || '#00f0ff'}; box-shadow:0 0 8px ${d.marker_color || '#00f0ff'};"></span>
                    ${d.indicator === "ALERT_CRITICAL" ? "CRITICAL THREAT" : d.indicator === "ALERT_WARNING" ? "WARNING NODE" : "VERIFIED NODE"}
                  </div>
                  <div><strong>IP:</strong> ${d.ip_address}</div>
                  <div><strong>Host:</strong> ${d.hostname}</div>
                  <div><strong>Location:</strong> ${d.display_location}</div>
                  <div><strong>Confidence:</strong> ${d.location_confidence}</div>
                  <div><strong>Open Ports:</strong> ${d.open_ports_count}</div>
                  ${d.alerts && d.alerts.length ? `<div style="color: #ef4444; margin-top: 4px; font-weight: bold;">⚠ ${d.alerts.length} Active Alert(s)</div>` : ""}
                  <div style="margin-top: 6px; font-size: 10px; color: #00f0ff; font-style: italic;">
                    &bull; Click to inspect device forensics & AI analyst
                  </div>
                </div>
              `}
              // Glowing Cyan Network Connection Arcs
              arcsData={connectionArcs}
              arcStartLat="start_lat"
              arcStartLng="start_lng"
              arcEndLat="end_lat"
              arcEndLng="end_lng"
              arcColor={(d: any) => d.color || "#00f0ff"}
              arcAltitude={(d: any) => (d.protocol.includes("SYN") ? 0.35 : 0.22)}
              arcStroke={1.4}
              arcDashLength={0.35}
              arcDashGap={0.2}
              arcDashAnimateTime={(d: any) => (d.color === "#ef4444" ? 1200 : 2200)}
              arcLabel={(d: any) => `
                <div style="
                  background: rgba(8, 16, 11, 0.96);
                  border: 1px solid ${d.color || '#00f0ff'};
                  box-shadow: 0 0 16px rgba(0, 240, 255, 0.3);
                  padding: 8px 12px;
                  border-radius: 6px;
                  font-family: monospace;
                  font-size: 11px;
                  color: #e2e8f0;
                  backdrop-filter: blur(12px);
                ">
                  <div style="color: ${d.color || '#00f0ff'}; font-weight: bold; margin-bottom: 2px;">
                    [Network Telemetry Stream]
                  </div>
                  <div>Flow: <strong>${d.source_ip}</strong> &rarr; <strong>${d.target_ip}</strong></div>
                  <div>Protocol: ${d.protocol} | Port: ${d.port}</div>
                  <div>Source: ${d.telemetry_source}</div>
                  ${d.bytes_transferred ? `<div>Transferred: ${(d.bytes_transferred / 1024).toFixed(1)} KB</div>` : ""}
                </div>
              `}
              // Concentric Pulsing Sonar Alert Beacons
              ringsData={ringsData}
              ringLat="lat"
              ringLng="lng"
              ringColor="color"
              ringMaxRadius="maxR"
              ringPropagationSpeed="propagationSpeed"
              ringRepeatPeriod="repeatPeriod"
            />
          )}
        </div>
      )}

      {/* Virtual LAN Topology Layer (Dedicated for RFC 1918 Private Enclaves) */}
      {(viewMode === "lan" || viewMode === "split") && (
        <div className={`lan-topology-layer ${viewMode === "split" ? "split-right" : "full"}`}>
          <div className="lan-topology-header">
            <div className="lan-badge">
              <Shield size={14} style={{ color: "var(--nvidia-green)" }} />
              <span>PRIVATE NETWORK TOPOLOGY (RFC 1918)</span>
            </div>
            <small className="lan-boundary-notice">
              Non-Geolocated Enclave &bull; Strictly Isolated from Earth Coordinates
            </small>
          </div>

          <div className="lan-nodes-grid">
            {virtualLanNodes.length === 0 ? (
              <div className="empty-lan-state">
                <Wifi size={28} className="text-slate-500" />
                <p>No private LAN devices discovered yet in local scope.</p>
                <small>Run a targeted scan against 192.168.1.0/24 or 127.0.0.1 to populate.</small>
              </div>
            ) : (
              virtualLanNodes.map(node => {
                const isSelected = selectedNode?.id === node.id;
                const hasAlert = node.alerts && node.alerts.length > 0;
                const isGateway = node.virtual_role === "GATEWAY" || node.ip_address.endsWith(".1");

                return (
                  <div
                    key={node.id}
                    className={`lan-device-card ${isSelected ? "selected" : ""} ${hasAlert ? "alert-card" : ""}`}
                    onClick={() => onSelectNode(node)}
                  >
                    <div className="device-header">
                      <div className="device-icon-wrap">
                        {isGateway ? (
                          <Radio size={16} style={{ color: "var(--nvidia-neon)" }} />
                        ) : node.virtual_role === "SERVER" ? (
                          <Server size={16} style={{ color: "var(--nvidia-green)" }} />
                        ) : (
                          <Laptop size={16} style={{ color: "var(--text-muted)" }} />
                        )}
                      </div>
                      <div className="device-title">
                        <strong>{node.ip_address}</strong>
                        <span>{node.hostname || "local-host"}</span>
                      </div>
                      <span className={`status-pill ${node.status.toLowerCase()}`}>
                        {node.status}
                      </span>
                    </div>

                    <div className="device-meta">
                      <div className="meta-item">
                        <span className="meta-label">ROLE:</span>
                        <span className="meta-val">{node.virtual_role || "WORKSTATION"}</span>
                      </div>
                      <div className="meta-item">
                        <span className="meta-label">OPEN PORTS:</span>
                        <span className="meta-val highlight">{node.open_ports_count}</span>
                      </div>
                      <div className="meta-item">
                        <span className="meta-label">BASELINE:</span>
                        <span className={`meta-val ${node.in_baseline ? "text-emerald-400" : "text-amber-400"}`}>
                          {node.in_baseline ? "Approved" : "Unapproved"}
                        </span>
                      </div>
                    </div>

                    {node.open_ports && node.open_ports.length > 0 && (
                      <div className="ports-badges-row">
                        {node.open_ports.slice(0, 4).map((p, pIdx) => (
                          <span key={pIdx} className="port-chip">
                            :{p.port} ({p.service_name})
                          </span>
                        ))}
                        {node.open_ports.length > 4 && (
                          <span className="port-chip more">+{node.open_ports.length - 4}</span>
                        )}
                      </div>
                    )}

                    {hasAlert && (
                      <div className="device-alert-banner">
                        <AlertTriangle size={12} className="text-red-400" />
                        <span>{node.alerts[0].title.slice(0, 42)}...</span>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Floating Interactive 3D Earth Navigation & Aesthetic Controls */}
      <div className="globe-camera-controls">
        {/* Play / Pause Rotation */}
        <button
          className={`cam-btn ${autoRotate ? "active" : ""}`}
          onClick={onToggleAutoRotate}
          title={autoRotate ? "Pause Continuous Rotation" : "Resume Continuous Rotation"}
        >
          {autoRotate ? <Pause size={14} /> : <Play size={14} />}
          <span>{autoRotate ? "ROTATING" : "PAUSED"}</span>
        </button>

        {/* Zoom In */}
        <button className="cam-btn" onClick={handleZoomIn} title="Zoom In (or Mouse Wheel Up)">
          <ZoomIn size={14} />
        </button>

        {/* Zoom Out */}
        <button className="cam-btn" onClick={handleZoomOut} title="Zoom Out (or Mouse Wheel Down)">
          <ZoomOut size={14} />
        </button>

        {/* Reset View */}
        <button className="cam-btn" onClick={handleResetCamera} title="Reset Global Perspective">
          <RotateCcw size={14} />
          <span>RESET</span>
        </button>

        {/* Rotation Speed Selector */}
        <div className="cam-speed-pill">
          <button
            className={`speed-option ${rotationSpeed === 0.3 ? "active" : ""}`}
            onClick={() => setRotationSpeed(0.3)}
            title="Slow Cinematic Rotation (0.3x)"
          >
            0.3x
          </button>
          <button
            className={`speed-option ${rotationSpeed === 0.6 ? "active" : ""}`}
            onClick={() => setRotationSpeed(0.6)}
            title="Normal Rotation (0.6x)"
          >
            0.6x
          </button>
          <button
            className={`speed-option ${rotationSpeed === 1.2 ? "active" : ""}`}
            onClick={() => setRotationSpeed(1.2)}
            title="Fast Rotation (1.2x)"
          >
            1.2x
          </button>
        </div>

        {/* Earth Texture Preset Switcher Dropdown */}
        <div className="earth-style-dropdown-wrap">
          <button
            className="cam-btn style-toggle-btn"
            onClick={() => setShowStyleMenu(prev => !prev)}
            title="Switch Earth Texture Style"
          >
            <Sparkles size={14} style={{ color: "#00f0ff" }} />
            <span>TEXTURE</span>
          </button>

          {showStyleMenu && (
            <div className="earth-style-menu">
              <div className="style-menu-header">EARTH RENDERING THEME</div>
              {(Object.keys(TEXTURE_OPTIONS) as EarthTextureStyle[]).map(key => (
                <button
                  key={key}
                  className={`style-menu-item ${textureStyle === key ? "active" : ""}`}
                  onClick={() => {
                    setTextureStyle(key);
                    setShowStyleMenu(false);
                  }}
                >
                  <span className="style-dot" />
                  <span>{TEXTURE_OPTIONS[key].name}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
