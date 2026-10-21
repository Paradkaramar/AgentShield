import React, { useState, useEffect } from "react";
import {
  Globe, CloudSun, ShieldAlert, Newspaper, Monitor, Search, RefreshCw,
  ExternalLink, Calendar, MapPin, Wind, Droplets, CheckCircle2, AlertTriangle,
  ArrowRight, ShieldCheck, Clock, Terminal, ChevronRight, Sparkles, Filter
} from "lucide-react";
import {
  fetchLiveWeather, fetchLiveCyberAdvisories, fetchLiveNews,
  performLiveResearch, fetchWindowsUpdates, fetchLiveHistory
} from "../../api";
import {
  LiveWeatherResult, LiveCyberAdvisory, LiveNewsArticle,
  WindowsUpdateIntel, LiveQueryHistoryItem, JarvisLanguage
} from "../../types";

interface Props {
  onAskAmoja?: (query: string) => void;
}

export const LiveIntelligenceHub: React.FC<Props> = ({ onAskAmoja }) => {
  // Navigation / Filter States
  const [activeSection, setActiveSection] = useState<"all" | "weather" | "cyber" | "news" | "windows" | "research" | "history">("all");
  
  // Refresh & Timestamps
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<string>(new Date().toLocaleTimeString());

  // Weather State
  const [weatherCity, setWeatherCity] = useState("Pune");
  const [weatherInput, setWeatherInput] = useState("Pune");
  const [weatherData, setWeatherData] = useState<LiveWeatherResult | null>(null);
  const [weatherLoading, setWeatherLoading] = useState(false);

  // Cybersecurity Advisories State
  const [advisories, setAdvisories] = useState<LiveCyberAdvisory[]>([]);
  const [cveSearch, setCveSearch] = useState("");
  const [totalCveRecords, setTotalCveRecords] = useState(0);
  const [cyberLoading, setCyberLoading] = useState(false);

  // News State
  const [newsTopic, setNewsTopic] = useState("all");
  const [newsFreshness, setNewsFreshness] = useState("week");
  const [articles, setArticles] = useState<LiveNewsArticle[]>([]);
  const [newsLoading, setNewsLoading] = useState(false);

  // Windows Update State
  const [windowsIntel, setWindowsIntel] = useState<WindowsUpdateIntel | null>(null);
  const [windowsLoading, setWindowsLoading] = useState(false);

  // Deep Web Research State
  const [researchQuery, setResearchQuery] = useState("");
  const [researchLang, setResearchLang] = useState<JarvisLanguage>("auto");
  const [researchLoading, setResearchLoading] = useState(false);
  const [researchResult, setResearchResult] = useState<{
    query: string;
    synthesis: string;
    spoken_summary: string;
    citations: any[];
    retrieved_at?: string;
  } | null>(null);

  // Audit History State
  const [historyItems, setHistoryItems] = useState<LiveQueryHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Initial Load
  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setIsRefreshing(true);
    await Promise.allSettled([
      loadWeather(weatherCity),
      loadCyberAdvisories(),
      loadNews(newsTopic, newsFreshness),
      loadWindowsUpdates(),
      loadHistory()
    ]);
    setIsRefreshing(false);
    setLastRefreshed(new Date().toLocaleTimeString());
  };

  const loadWeather = async (city: string) => {
    setWeatherLoading(true);
    try {
      const res = await fetchLiveWeather(city);
      setWeatherData(res);
      setWeatherCity(city);
    } catch (e) {
      console.error("Weather error:", e);
    } finally {
      setWeatherLoading(false);
    }
  };

  const loadCyberAdvisories = async (search?: string) => {
    setCyberLoading(true);
    try {
      const res = await fetchLiveCyberAdvisories(search, 12);
      setAdvisories(res.advisories || []);
      setTotalCveRecords(res.total_source_records || 0);
    } catch (e) {
      console.error("Advisories error:", e);
    } finally {
      setCyberLoading(false);
    }
  };

  const loadNews = async (topic: string, freshness: string) => {
    setNewsLoading(true);
    try {
      const res = await fetchLiveNews(topic, freshness, 9);
      setArticles(res.articles || []);
    } catch (e) {
      console.error("News error:", e);
    } finally {
      setNewsLoading(false);
    }
  };

  const loadWindowsUpdates = async () => {
    setWindowsLoading(true);
    try {
      const res = await fetchWindowsUpdates();
      setWindowsIntel(res);
    } catch (e) {
      console.error("Windows update error:", e);
    } finally {
      setWindowsLoading(false);
    }
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchLiveHistory(15);
      setHistoryItems(res.queries || []);
    } catch (e) {
      console.error("History error:", e);
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleResearchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!researchQuery.trim() || researchLoading) return;
    setResearchLoading(true);
    try {
      const res = await performLiveResearch(researchQuery.trim(), researchLang);
      setResearchResult(res);
      loadHistory();
    } catch (e) {
      console.error("Research error:", e);
    } finally {
      setResearchLoading(false);
    }
  };

  const cityPresets = ["Pune", "Mumbai", "Delhi", "Bengaluru", "London", "New York"];

  return (
    <div className="live-intelligence-hub" style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "20px", color: "#e2e8f0" }}>
      {/* Top Banner Toolbar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px", background: "rgba(15, 23, 42, 0.75)", padding: "16px 20px", borderRadius: "8px", border: "1px solid rgba(56, 189, 248, 0.3)" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Globe size={22} style={{ color: "#38bdf8" }} />
            <h2 style={{ margin: 0, fontSize: "18px", fontWeight: 700, letterSpacing: "0.5px", color: "#38bdf8" }}>
              AMOJA AI // LIVE INTELLIGENCE & REAL-TIME KNOWLEDGE ENGINE
            </h2>
          </div>
          <p style={{ margin: "4px 0 0 32px", fontSize: "12px", color: "#94a3b8" }}>
            Multi-Source Research • CISA KEV & NIST CVE Advisories • Open-Meteo Live Weather • Windows Health Updates • Zero-Trust Guardrails
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "11px", color: "#64748b" }}>
            Last Synced: <strong style={{ color: "#94a3b8" }}>{lastRefreshed}</strong>
          </span>
          <button
            type="button"
            onClick={loadAllData}
            disabled={isRefreshing}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "7px 14px",
              background: "rgba(56, 189, 248, 0.15)",
              border: "1px solid rgba(56, 189, 248, 0.4)",
              borderRadius: "6px",
              color: "#38bdf8",
              fontSize: "12px",
              fontWeight: 600,
              cursor: isRefreshing ? "not-allowed" : "pointer"
            }}
          >
            <RefreshCw size={13} className={isRefreshing ? "spin" : ""} />
            <span>{isRefreshing ? "Synchronizing..." : "Refresh Live Feeds"}</span>
          </button>
        </div>
      </div>

      {/* Navigation Filter Tabs */}
      <div style={{ display: "flex", gap: "8px", overflowX: "auto", paddingBottom: "4px" }}>
        {[
          { id: "all", label: "Full Overview", icon: Sparkles },
          { id: "weather", label: "Live Weather", icon: CloudSun },
          { id: "cyber", label: `CISA & CVEs (${advisories.length})`, icon: ShieldAlert },
          { id: "news", label: "News & Tech Releases", icon: Newspaper },
          { id: "windows", label: "Windows Health & Updates", icon: Monitor },
          { id: "research", label: "Deep Web Research", icon: Search },
          { id: "history", label: "Query Audit Log", icon: Clock }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeSection === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveSection(tab.id as any)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "8px 14px",
                fontSize: "12px",
                fontWeight: 600,
                borderRadius: "6px",
                cursor: "pointer",
                background: isActive ? "rgba(56, 189, 248, 0.2)" : "rgba(15, 23, 42, 0.6)",
                border: `1px solid ${isActive ? "#38bdf8" : "rgba(255, 255, 255, 0.1)"}`,
                color: isActive ? "#38bdf8" : "#94a3b8",
                whiteSpace: "nowrap"
              }}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* SECTION 1: LIVE WEATHER CARD */}
      {(activeSection === "all" || activeSection === "weather") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(56, 189, 248, 0.25)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <CloudSun size={18} style={{ color: "#38bdf8" }} />
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#38bdf8" }}>
                LIVE WEATHER & FORECASTS // OPEN-METEO ENGINE
              </h3>
            </div>

            {/* City Search & Presets */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <div style={{ display: "flex", gap: "4px" }}>
                {cityPresets.map(c => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => { setWeatherInput(c); loadWeather(c); }}
                    style={{
                      fontSize: "11px",
                      padding: "3px 8px",
                      borderRadius: "4px",
                      background: weatherCity.toLowerCase() === c.toLowerCase() ? "rgba(56, 189, 248, 0.25)" : "rgba(255, 255, 255, 0.06)",
                      border: "1px solid rgba(56, 189, 248, 0.3)",
                      color: weatherCity.toLowerCase() === c.toLowerCase() ? "#38bdf8" : "#cbd5e1",
                      cursor: "pointer"
                    }}
                  >
                    {c}
                  </button>
                ))}
              </div>

              <form
                onSubmit={(e) => { e.preventDefault(); if (weatherInput.trim()) loadWeather(weatherInput.trim()); }}
                style={{ display: "flex", gap: "4px" }}
              >
                <input
                  type="text"
                  value={weatherInput}
                  onChange={(e) => setWeatherInput(e.target.value)}
                  placeholder="Enter city..."
                  style={{
                    padding: "4px 8px",
                    fontSize: "12px",
                    borderRadius: "4px",
                    background: "rgba(0,0,0,0.4)",
                    border: "1px solid rgba(255, 255, 255, 0.2)",
                    color: "#fff",
                    width: "120px"
                  }}
                />
                <button
                  type="submit"
                  style={{
                    padding: "4px 10px",
                    fontSize: "11px",
                    borderRadius: "4px",
                    background: "#38bdf8",
                    color: "#000",
                    fontWeight: 700,
                    border: "none",
                    cursor: "pointer"
                  }}
                >
                  Search
                </button>
              </form>
            </div>
          </div>

          {weatherLoading ? (
            <div style={{ padding: "20px", textAlign: "center", color: "#94a3b8", fontSize: "13px" }}>
              Retrieving live meteorological telemetry...
            </div>
          ) : weatherData && weatherData.status === "success" ? (
            <div>
              {weatherData.is_severe && (
                <div style={{ marginBottom: "12px", padding: "8px 12px", background: "rgba(239, 68, 68, 0.2)", border: "1px solid #ef4444", borderRadius: "6px", display: "flex", alignItems: "center", gap: "8px", color: "#fca5a5", fontSize: "12px" }}>
                  <AlertTriangle size={16} />
                  <strong>Severe Weather Alert: Active storm or high wind velocity detected for this coordinate.</strong>
                </div>
              )}

              {/* Main Weather Card */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", marginBottom: "14px" }}>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#94a3b8" }}>
                    <MapPin size={12} />
                    <span>Location</span>
                  </div>
                  <div style={{ fontSize: "18px", fontWeight: 700, color: "#fff", marginTop: "4px" }}>
                    {weatherData.city}, {weatherData.country}
                  </div>
                  <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                    {weatherData.observation_time?.replace("T", " ")}
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.3)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Condition</div>
                  <div style={{ fontSize: "16px", fontWeight: 700, color: "#38bdf8", marginTop: "4px" }}>
                    {weatherData.icon} {weatherData.condition}
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "2px" }}>
                    मराठी: {weatherData.condition_mr} • हिन्दी: {weatherData.condition_hi}
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.3)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Temperature</div>
                  <div style={{ fontSize: "22px", fontWeight: 800, color: "#f59e0b", marginTop: "2px" }}>
                    {weatherData.temperature_c}°C
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>
                    Feels like: {weatherData.apparent_temperature_c}°C
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.3)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#94a3b8" }}>
                    <Droplets size={12} />
                    <span>Atmospheric Telemetry</span>
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: "#fff", marginTop: "6px" }}>
                    Humidity: <strong style={{ color: "#38bdf8" }}>{weatherData.humidity_percent}%</strong>
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: "#fff", marginTop: "2px" }}>
                    Wind: <strong style={{ color: "#38bdf8" }}>{weatherData.wind_speed_kmh} km/h</strong>
                  </div>
                </div>
              </div>

              {/* 4-Day Forecast Strip */}
              {weatherData.daily_forecast && weatherData.daily_forecast.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#94a3b8", marginBottom: "8px", textTransform: "uppercase" }}>
                    4-Day Forecast Model
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "8px" }}>
                    {weatherData.daily_forecast.slice(0, 4).map((f, fIdx) => (
                      <div key={fIdx} style={{ background: "rgba(0,0,0,0.25)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)", textAlign: "center" }}>
                        <div style={{ fontSize: "11px", fontWeight: 700, color: "#cbd5e1" }}>
                          {f.date.slice(5)}
                        </div>
                        <div style={{ fontSize: "18px", margin: "4px 0" }}>{f.icon}</div>
                        <div style={{ fontSize: "11px", color: "#94a3b8", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          {f.condition}
                        </div>
                        <div style={{ fontSize: "12px", fontWeight: 700, color: "#f59e0b", marginTop: "4px" }}>
                          {f.max_c}° / <span style={{ color: "#64748b" }}>{f.min_c}°</span>
                        </div>
                        <div style={{ fontSize: "10px", color: "#38bdf8", marginTop: "2px" }}>
                          💧 {f.rain_probability}% Rain
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Button */}
              {onAskAmoja && (
                <div style={{ marginTop: "12px", display: "flex", justifyContent: "flex-end" }}>
                  <button
                    type="button"
                    onClick={() => onAskAmoja(`Amoja, ${weatherData.city} ka live weather aur forecast samjhao`)}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "6px",
                      fontSize: "11px",
                      padding: "5px 10px",
                      background: "rgba(56, 189, 248, 0.15)",
                      border: "1px solid rgba(56, 189, 248, 0.4)",
                      borderRadius: "4px",
                      color: "#38bdf8",
                      cursor: "pointer"
                    }}
                  >
                    <span>Ask AMOJA about this weather</span>
                    <ArrowRight size={11} />
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div style={{ padding: "16px", color: "#f87171", fontSize: "12px" }}>
              Unable to load weather. Verify location name or check internet connection.
            </div>
          )}
        </div>
      )}

      {/* SECTION 2: CYBERSECURITY ADVISORIES (CISA KEV & NIST CVE) */}
      {(activeSection === "all" || activeSection === "cyber") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <ShieldAlert size={18} style={{ color: "#ef4444" }} />
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#f87171" }}>
                CISA KNOWN EXPLOITED VULNERABILITIES & CVE ADVISORIES
              </h3>
              {totalCveRecords > 0 && (
                <span style={{ fontSize: "10px", padding: "2px 6px", background: "rgba(239, 68, 68, 0.2)", color: "#fca5a5", borderRadius: "4px", border: "1px solid rgba(239, 68, 68, 0.4)", fontWeight: 700 }}>
                  {totalCveRecords.toLocaleString()}+ KEV RECORDS
                </span>
              )}
            </div>

            {/* CVE Search */}
            <form
              onSubmit={(e) => { e.preventDefault(); loadCyberAdvisories(cveSearch.trim()); }}
              style={{ display: "flex", gap: "6px" }}
            >
              <input
                type="text"
                value={cveSearch}
                onChange={(e) => setCveSearch(e.target.value)}
                placeholder="Search CVE-..., Microsoft, Chrome..."
                style={{
                  padding: "4px 8px",
                  fontSize: "12px",
                  borderRadius: "4px",
                  background: "rgba(0,0,0,0.4)",
                  border: "1px solid rgba(255, 255, 255, 0.2)",
                  color: "#fff",
                  width: "180px"
                }}
              />
              <button
                type="submit"
                style={{
                  padding: "4px 10px",
                  fontSize: "11px",
                  borderRadius: "4px",
                  background: "#ef4444",
                  color: "#fff",
                  fontWeight: 700,
                  border: "none",
                  cursor: "pointer"
                }}
              >
                Filter CVE
              </button>
            </form>
          </div>

          {/* Zero-Trust Security Rule Notice */}
          <div style={{ marginBottom: "14px", padding: "8px 12px", background: "rgba(245, 158, 11, 0.12)", border: "1px solid rgba(245, 158, 11, 0.35)", borderRadius: "6px", display: "flex", alignItems: "center", gap: "8px", fontSize: "11px", color: "#fbbf24" }}>
            <ShieldCheck size={14} />
            <span>
              <strong>Zero-Trust Guardrail:</strong> Advisory feed provides verified intelligence only. AMOJA will never automatically alter firewall settings or install software fixes without explicit user confirmation.
            </span>
          </div>

          {cyberLoading ? (
            <div style={{ padding: "20px", textAlign: "center", color: "#94a3b8", fontSize: "13px" }}>
              Loading CISA Known Exploited Vulnerability catalog...
            </div>
          ) : advisories.length === 0 ? (
            <div style={{ padding: "16px", color: "#94a3b8", fontSize: "12px" }}>
              No CVE advisories matching filter. Try searching "CVE-2024" or clear the search.
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "10px" }}>
              {advisories.slice(0, 6).map((adv, idx) => (
                <div key={idx} style={{ background: "rgba(0,0,0,0.3)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                      <span style={{ fontSize: "12px", fontWeight: 800, color: "#f87171" }}>
                        {adv.cve_id}
                      </span>
                      <span style={{ fontSize: "9px", padding: "1px 5px", background: "rgba(239, 68, 68, 0.2)", color: "#fca5a5", borderRadius: "3px", fontWeight: 700 }}>
                        {adv.exploitation_status || "ACTIVE EXPLOITATION"}
                      </span>
                    </div>

                    <div style={{ fontSize: "12px", fontWeight: 600, color: "#fff", marginBottom: "4px" }}>
                      {adv.vendor_product}
                    </div>

                    <p style={{ fontSize: "11px", color: "#94a3b8", margin: "0 0 8px 0", lineHeight: "1.4" }}>
                      {adv.short_description ? adv.short_description.slice(0, 140) + "..." : "Official vulnerability advisory record."}
                    </p>

                    {adv.required_action && (
                      <div style={{ fontSize: "10px", color: "#fbbf24", marginBottom: "8px", background: "rgba(245, 158, 11, 0.08)", padding: "4px 6px", borderRadius: "4px" }}>
                        <strong>Action:</strong> {adv.required_action}
                      </div>
                    )}
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: "8px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                    <span style={{ fontSize: "10px", color: "#64748b" }}>
                      Added: {adv.date_added || "Recent"}
                    </span>
                    <div style={{ display: "flex", gap: "6px" }}>
                      {adv.url && (
                        <a
                          href={adv.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ fontSize: "10px", color: "#38bdf8", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "2px" }}
                        >
                          <span>Advisory</span>
                          <ExternalLink size={10} />
                        </a>
                      )}
                      {onAskAmoja && (
                        <button
                          type="button"
                          onClick={() => onAskAmoja(`Amoja, investigate vulnerability ${adv.cve_id} for ${adv.vendor_product} and explain the official fix`)}
                          style={{ fontSize: "10px", padding: "2px 6px", background: "rgba(56, 189, 248, 0.15)", border: "1px solid rgba(56, 189, 248, 0.3)", borderRadius: "3px", color: "#38bdf8", cursor: "pointer" }}
                        >
                          Investigate
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SECTION 3: LIVE NEWS & TECHNOLOGY INTELLIGENCE STREAM */}
      {(activeSection === "all" || activeSection === "news") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(16, 185, 129, 0.25)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Newspaper size={18} style={{ color: "#10b981" }} />
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#34d399" }}>
                LIVE NEWS & TECHNOLOGY INTELLIGENCE STREAM
              </h3>
            </div>

            {/* Filters: Topic & Freshness */}
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              <div style={{ display: "flex", gap: "4px" }}>
                {[
                  { id: "all", label: "All" },
                  { id: "ai", label: "AI Models" },
                  { id: "tech", label: "Tech Launches" },
                  { id: "cybersecurity", label: "Cyber Threats" },
                  { id: "india_world", label: "India & World" }
                ].map(t => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => { setNewsTopic(t.id); loadNews(t.id, newsFreshness); }}
                    style={{
                      fontSize: "11px",
                      padding: "3px 8px",
                      borderRadius: "4px",
                      background: newsTopic === t.id ? "rgba(16, 185, 129, 0.25)" : "rgba(255, 255, 255, 0.06)",
                      border: "1px solid rgba(16, 185, 129, 0.3)",
                      color: newsTopic === t.id ? "#34d399" : "#cbd5e1",
                      cursor: "pointer"
                    }}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div style={{ display: "flex", gap: "4px" }}>
                {[
                  { id: "today", label: "Today" },
                  { id: "week", label: "This Week" },
                  { id: "month", label: "Month" }
                ].map(f => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => { setNewsFreshness(f.id); loadNews(newsTopic, f.id); }}
                    style={{
                      fontSize: "10px",
                      padding: "3px 6px",
                      borderRadius: "4px",
                      background: newsFreshness === f.id ? "rgba(255, 255, 255, 0.15)" : "transparent",
                      border: "1px solid rgba(255, 255, 255, 0.15)",
                      color: newsFreshness === f.id ? "#fff" : "#94a3b8",
                      cursor: "pointer"
                    }}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {newsLoading ? (
            <div style={{ padding: "20px", textAlign: "center", color: "#94a3b8", fontSize: "13px" }}>
              Scanning official feeds and news sources...
            </div>
          ) : articles.length === 0 ? (
            <div style={{ padding: "16px", color: "#94a3b8", fontSize: "12px" }}>
              No current articles retrieved for this topic. Try selecting "All" or expanding the time window.
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "10px" }}>
              {articles.slice(0, 6).map((art, idx) => (
                <div key={idx} style={{ background: "rgba(0,0,0,0.3)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                      <span style={{ fontSize: "10px", fontWeight: 700, color: "#34d399", background: "rgba(16, 185, 129, 0.12)", padding: "2px 5px", borderRadius: "3px" }}>
                        {art.publisher || "Verified Publisher"}
                      </span>
                      <span style={{ fontSize: "10px", color: "#64748b" }}>
                        {art.publication_date?.slice(0, 10) || "Recent"}
                      </span>
                    </div>

                    <a
                      href={art.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ fontSize: "13px", fontWeight: 600, color: "#fff", textDecoration: "none", display: "block", marginBottom: "6px", lineHeight: "1.3" }}
                    >
                      {art.title}
                    </a>

                    <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: "1.4" }}>
                      {art.snippet ? art.snippet.slice(0, 120) + "..." : "Click to view full primary coverage."}
                    </p>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "10px", paddingTop: "8px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                    <a
                      href={art.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ fontSize: "10px", color: "#38bdf8", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "2px" }}
                    >
                      <span>Read Source</span>
                      <ExternalLink size={10} />
                    </a>

                    {onAskAmoja && (
                      <button
                        type="button"
                        onClick={() => onAskAmoja(`Amoja, is news ke baare mein detail samjhao: "${art.title}"`)}
                        style={{ fontSize: "10px", padding: "2px 6px", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.3)", borderRadius: "3px", color: "#34d399", cursor: "pointer" }}
                      >
                        Ask AMOJA
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SECTION 4: WINDOWS & SOFTWARE HEALTH INTELLIGENCE */}
      {(activeSection === "all" || activeSection === "windows") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(168, 85, 247, 0.3)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Monitor size={18} style={{ color: "#c084fc" }} />
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#c084fc" }}>
                WINDOWS & SOFTWARE UPDATE INTELLIGENCE (TRIPARTITE VERIFICATION)
              </h3>
            </div>
            <span style={{ fontSize: "10px", padding: "2px 6px", background: "rgba(168, 85, 247, 0.2)", color: "#e9d5ff", borderRadius: "4px", border: "1px solid rgba(168, 85, 247, 0.4)", fontWeight: 700 }}>
              OFFICIAL MS HEALTH STATUS
            </span>
          </div>

          {windowsLoading ? (
            <div style={{ padding: "20px", textAlign: "center", color: "#94a3b8", fontSize: "13px" }}>
              Inspecting Windows release health and device configuration...
            </div>
          ) : windowsIntel ? (
            <div>
              {/* Tripartite Distinction Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", marginBottom: "12px" }}>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#38bdf8", textTransform: "uppercase" }}>
                    1. Public Advisory / Release
                  </div>
                  <div style={{ fontSize: "12px", color: "#e2e8f0", marginTop: "6px" }}>
                    {windowsIntel.update_distinction?.public_advisory_status}
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                    Latest Patch Tuesday: <strong style={{ color: "#fff" }}>{windowsIntel.official_release_status?.latest_patch_tuesday}</strong>
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.3)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#fbbf24", textTransform: "uppercase" }}>
                    2. Device Availability
                  </div>
                  <div style={{ fontSize: "12px", color: "#e2e8f0", marginTop: "6px" }}>
                    {windowsIntel.update_distinction?.device_availability}
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                    Hardware checks via Windows Update Agent
                  </div>
                </div>

                <div style={{ background: "rgba(0,0,0,0.3)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#34d399", textTransform: "uppercase" }}>
                    3. Local Installed OS State
                  </div>
                  <div style={{ fontSize: "12px", color: "#e2e8f0", marginTop: "6px" }}>
                    {windowsIntel.installed_on_device?.os_version}
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                    Host: <strong style={{ color: "#fff" }}>{windowsIntel.installed_on_device?.hostname || "Local Machine"}</strong>
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "#94a3b8", paddingTop: "8px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                <span>Official Health Portal: <a href={windowsIntel.official_release_status?.official_health_url} target="_blank" rel="noopener noreferrer" style={{ color: "#38bdf8" }}>learn.microsoft.com/windows/release-health</a></span>
                {onAskAmoja && (
                  <button
                    type="button"
                    onClick={() => onAskAmoja("Amoja, check my Windows 11 update health and explain if any security patches are recommended")}
                    style={{ fontSize: "11px", padding: "4px 8px", background: "rgba(168, 85, 247, 0.15)", border: "1px solid rgba(168, 85, 247, 0.4)", borderRadius: "4px", color: "#e9d5ff", cursor: "pointer" }}
                  >
                    Check Windows Updates with AMOJA
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div style={{ padding: "16px", color: "#94a3b8", fontSize: "12px" }}>
              Unable to read Windows release telemetry.
            </div>
          )}
        </div>
      )}

      {/* SECTION 5: LIVE WEB RESEARCH & CITATIONS ENGINE */}
      {(activeSection === "all" || activeSection === "research") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(56, 189, 248, 0.3)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
            <Search size={18} style={{ color: "#38bdf8" }} />
            <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#38bdf8" }}>
              LIVE WEB RESEARCH ENGINE (MULTI-SOURCE CITATIONS)
            </h3>
          </div>

          <form onSubmit={handleResearchSubmit} style={{ display: "flex", gap: "8px", marginBottom: "14px", flexWrap: "wrap" }}>
            <input
              type="text"
              value={researchQuery}
              onChange={(e) => setResearchQuery(e.target.value)}
              placeholder="Ask any current event or research query (e.g. 'What is the latest open-source AI release this week?')"
              style={{
                flex: 1,
                minWidth: "260px",
                padding: "8px 12px",
                fontSize: "13px",
                borderRadius: "6px",
                background: "rgba(0,0,0,0.5)",
                border: "1px solid rgba(56, 189, 248, 0.3)",
                color: "#fff"
              }}
            />

            <select
              value={researchLang}
              onChange={(e) => setResearchLang(e.target.value as any)}
              style={{
                padding: "8px 12px",
                fontSize: "12px",
                borderRadius: "6px",
                background: "rgba(0,0,0,0.5)",
                border: "1px solid rgba(255, 255, 255, 0.2)",
                color: "#fff"
              }}
            >
              <option value="auto">Auto Language</option>
              <option value="en">English</option>
              <option value="hi">हिन्दी (Hindi)</option>
              <option value="mr">मराठी (Marathi)</option>
              <option value="hinglish">Hinglish</option>
            </select>

            <button
              type="submit"
              disabled={researchLoading || !researchQuery.trim()}
              style={{
                padding: "8px 16px",
                fontSize: "12px",
                fontWeight: 700,
                borderRadius: "6px",
                background: "#38bdf8",
                color: "#000",
                border: "none",
                cursor: researchLoading ? "not-allowed" : "pointer",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px"
              }}
            >
              <Search size={13} />
              <span>{researchLoading ? "Researching..." : "Perform Live Research"}</span>
            </button>
          </form>

          {researchResult && (
            <div style={{ background: "rgba(0,0,0,0.4)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <span style={{ fontSize: "11px", fontWeight: 700, color: "#38bdf8" }}>
                  RESEARCH SYNTHESIS // {researchResult.query}
                </span>
                <span style={{ fontSize: "10px", color: "#64748b" }}>
                  {researchResult.retrieved_at}
                </span>
              </div>

              <div style={{ fontSize: "13px", color: "#e2e8f0", lineHeight: "1.5", whiteSpace: "pre-wrap", marginBottom: "12px" }}>
                {researchResult.synthesis}
              </div>

              {/* Citations */}
              {researchResult.citations && researchResult.citations.length > 0 && (
                <div style={{ paddingTop: "10px", borderTop: "1px solid rgba(255,255,255,0.08)" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#94a3b8", marginBottom: "6px" }}>
                    Verified Citations & Sources ({researchResult.citations.length})
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {researchResult.citations.map((c, cIdx) => (
                      <a
                        key={cIdx}
                        href={c.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "4px",
                          fontSize: "11px",
                          padding: "3px 8px",
                          background: "rgba(56, 189, 248, 0.12)",
                          border: "1px solid rgba(56, 189, 248, 0.3)",
                          borderRadius: "4px",
                          color: "#7dd3fc",
                          textDecoration: "none"
                        }}
                      >
                        <span>[{cIdx + 1}] {c.publisher || c.title || "Source"}</span>
                        <ExternalLink size={10} />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SECTION 6: LIVE QUERY AUDIT LOG */}
      {(activeSection === "all" || activeSection === "history") && (
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: "8px", padding: "18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Clock size={16} style={{ color: "#94a3b8" }} />
              <h3 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "#cbd5e1" }}>
                LIVE QUERY AUDIT & PROVENANCE LOG
              </h3>
            </div>
            <button
              type="button"
              onClick={loadHistory}
              style={{ fontSize: "10px", padding: "2px 6px", background: "transparent", border: "1px solid rgba(255,255,255,0.2)", borderRadius: "3px", color: "#94a3b8", cursor: "pointer" }}
            >
              Refresh Log
            </button>
          </div>

          {historyLoading ? (
            <div style={{ padding: "10px", textAlign: "center", color: "#64748b", fontSize: "11px" }}>Loading query audit...</div>
          ) : historyItems.length === 0 ? (
            <div style={{ fontSize: "11px", color: "#64748b" }}>No live intelligence queries logged yet.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", textAlign: "left", color: "#94a3b8" }}>
                    <th style={{ padding: "6px 8px" }}>Timestamp</th>
                    <th style={{ padding: "6px 8px" }}>Category</th>
                    <th style={{ padding: "6px 8px" }}>Query</th>
                    <th style={{ padding: "6px 8px" }}>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {historyItems.slice(0, 8).map((item, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", color: "#cbd5e1" }}>
                      <td style={{ padding: "6px 8px", color: "#64748b", whiteSpace: "nowrap" }}>{item.retrieved_at?.slice(11, 19)}</td>
                      <td style={{ padding: "6px 8px" }}>
                        <span style={{ padding: "1px 5px", borderRadius: "3px", background: "rgba(56, 189, 248, 0.12)", color: "#38bdf8", fontWeight: 600 }}>
                          {item.category}
                        </span>
                      </td>
                      <td style={{ padding: "6px 8px", maxWidth: "320px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.query_text}
                      </td>
                      <td style={{ padding: "6px 8px", color: "#94a3b8" }}>{item.latency_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
