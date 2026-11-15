import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Shield,
  LayoutDashboard,
  Bot,
  ShieldAlert,
  ScrollText,
  Fingerprint,
  Terminal,
  Settings,
  Bell,
  Search,
  ChevronDown,
  ArrowUpRight,
  LockKeyhole,
  Zap,
  CircleCheck,
  CircleAlert,
  RefreshCw,
  Clock3,
  XCircle,
} from "lucide-react";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

import { api } from "./services/api";
import type {
  SecurityEvent,
  IntegrityReport,
  AnomalyReport,
} from "./services/api";

import "./App.css";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Agent Monitoring", icon: Bot },
  { label: "Threat Detection", icon: ShieldAlert },
  { label: "Security Events", icon: ScrollText },
  { label: "Integrity Verification", icon: Fingerprint },
  { label: "Tool Activity", icon: Terminal },
];

function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityReport | null>(null);
  const [anomalyReport, setAnomalyReport] = useState<AnomalyReport | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [activeSection, setActiveSection] = useState("Overview");
  const [eventSearch, setEventSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const detailPanelRef = useRef<HTMLElement | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const [health, eventData, integrityData, anomalyData] =
        await Promise.all([
          api.getHealth(),
          api.getEvents(100),
          api.getIntegrity(),
          api.getAnomalies(),
        ]);

      setBackendOnline(health.status === "healthy");
      setEvents(eventData.events);
      setIntegrity(integrityData);
      setAnomalyReport(anomalyData);
      setLastUpdated(new Date());
    } catch (err) {
      setBackendOnline(false);
      setError(
        err instanceof Error ? err.message : "Unable to connect to AEGISGATE."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
  if (selectedEvent) {
    detailPanelRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }
}, [selectedEvent]);


  const blockedCount = events.filter(
    (event) => event.decision === "BLOCK"
  ).length;

  const approvalCount = events.filter(
    (event) => event.decision === "REQUIRE_APPROVAL"
  ).length;

  const agentStats = useMemo(() => {
  const agents = new Map<
    string,
    {
      agentId: string;
      total: number;
      allowed: number;
      blocked: number;
      approval: number;
      lastSeen: string;
      tools: Set<string>;
    }
  >();

  events.forEach((event) => {
    const existing = agents.get(event.agent_id);

    if (existing) {
      existing.total += 1;
      existing.tools.add(event.tool_name);

      if (event.decision === "ALLOW") existing.allowed += 1;
      if (event.decision === "BLOCK") existing.blocked += 1;
      if (event.decision === "REQUIRE_APPROVAL") existing.approval += 1;

      if (
        new Date(event.timestamp).getTime() >
        new Date(existing.lastSeen).getTime()
      ) {
        existing.lastSeen = event.timestamp;
      }
    } else {
      agents.set(event.agent_id, {
        agentId: event.agent_id,
        total: 1,
        allowed: event.decision === "ALLOW" ? 1 : 0,
        blocked: event.decision === "BLOCK" ? 1 : 0,
        approval: event.decision === "REQUIRE_APPROVAL" ? 1 : 0,
        lastSeen: event.timestamp,
        tools: new Set([event.tool_name]),
      });
    }
  });

  return Array.from(agents.values()).sort((a, b) => b.total - a.total);
}, [events]);

  const toolStats = useMemo(() => {
    const tools = new Map<
      string,
      {
        toolName: string;
        total: number;
        allowed: number;
        blocked: number;
        approval: number;
        executed: number;
        operations: Set<string>;
        lastSeen: string;
      }
    >();

    events.forEach((event) => {
      const existing = tools.get(event.tool_name);

      if (existing) {
        existing.total += 1;
        existing.operations.add(event.operation);

        if (event.decision === "ALLOW") existing.allowed += 1;
        if (event.decision === "BLOCK") existing.blocked += 1;
        if (event.decision === "REQUIRE_APPROVAL") existing.approval += 1;
        if (event.executed) existing.executed += 1;

        if (
          new Date(event.timestamp).getTime() >
          new Date(existing.lastSeen).getTime()
        ) {
          existing.lastSeen = event.timestamp;
        }
      } else {
        tools.set(event.tool_name, {
          toolName: event.tool_name,
          total: 1,
          allowed: event.decision === "ALLOW" ? 1 : 0,
          blocked: event.decision === "BLOCK" ? 1 : 0,
          approval: event.decision === "REQUIRE_APPROVAL" ? 1 : 0,
          executed: event.executed ? 1 : 0,
          operations: new Set([event.operation]),
          lastSeen: event.timestamp,
        });
      }
    });

    return Array.from(tools.values()).sort(
      (a, b) => b.total - a.total
    );
  }, [events]);

const highAnomalyCount =
  anomalyReport?.anomalies.filter(
    (anomaly) => anomaly.severity === "HIGH"
  ).length ?? 0;

const mediumAnomalyCount =
  anomalyReport?.anomalies.filter(
    (anomaly) => anomaly.severity === "MEDIUM"
  ).length ?? 0;

  const allowedCount = events.filter(
    (event) => event.decision === "ALLOW"
  ).length;

  const filteredEvents = useMemo(() => {
  const query = eventSearch.trim().toLowerCase();

  return events.filter((event) => {
    const matchesDecision =
      decisionFilter === "ALL" || event.decision === decisionFilter;

    const searchableText = [
      event.event_id,
      event.agent_id,
      event.tool_name,
      event.operation,
      event.resource ?? "",
    ].join(" ").toLowerCase();

    return matchesDecision && searchableText.includes(query);
  });
}, [events, eventSearch, decisionFilter]);

const decisionCounts = {
  ALL: events.length,
  ALLOW: events.filter((event) => event.decision === "ALLOW").length,
  BLOCK: events.filter((event) => event.decision === "BLOCK").length,
  REQUIRE_APPROVAL: events.filter(
    (event) => event.decision === "REQUIRE_APPROVAL"
  ).length,
};

  const chartData = useMemo(() => {
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - index));

      return {
        date: date.toLocaleDateString("en", { weekday: "short" }),
        fullDate: date.toDateString(),
        allowed: 0,
        blocked: 0,
        approval: 0,
      };
    });

    events.forEach((event) => {
      const eventDate = new Date(event.timestamp);

      const matchingDay = days.find(
        (day) => day.fullDate === eventDate.toDateString()
      );

      if (!matchingDay) return;

      if (event.decision === "ALLOW") matchingDay.allowed += 1;
      if (event.decision === "BLOCK") matchingDay.blocked += 1;
      if (event.decision === "REQUIRE_APPROVAL") matchingDay.approval += 1;
    });

    return days;
  }, [events]);

  const metrics = [
    {
      label: "Recent Security Events",
      value: events.length.toLocaleString(),
      detail: "Latest 100 events",
      icon: Activity,
      color: "cyan",
    },
    {
      label: "Blocked Requests",
      value: blockedCount.toLocaleString(),
      detail: "Within loaded events",
      icon: ShieldAlert,
      color: "red",
    },
    {
      label: "Detected Anomalies",
      value: anomalyReport?.total_anomalies ?? "—",
      detail: `${anomalyReport?.events_analyzed ?? 0} events analyzed`,
      icon: Zap,
      color: "purple",
    },
    {
      label: "Integrity Status",
      value: integrity ? (integrity.valid ? "Verified" : "Failed") : "—",
      detail: integrity
        ? `${integrity.checked_events} events hash-checked`
        : "Waiting for verification",
      icon: Fingerprint,
      color: integrity?.valid ? "green" : "red",
    },
  ];

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) return "Unknown";

    return date.toLocaleString();
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} />
          </div>
          <div>
            <h1>AEGISGATE</h1>
            <span>AI SECURITY PLATFORM</span>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>

        <nav className="navigation">
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
                <button
                   key={item.label}
                   onClick={() => setActiveSection(item.label)}
                   className={`nav-item ${
                     activeSection === item.label ? "active" : ""
                    }`}
                 >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <button className="nav-item">
            <Settings size={18} />
            <span>Settings</span>
          </button>

          <div className="system-status">
            <div className="status-heading">
              <span
                className={`status-dot ${backendOnline ? "" : "offline"}`}
              />
              {backendOnline ? "SYSTEM OPERATIONAL" : "SYSTEM OFFLINE"}
            </div>
            <p>
              {backendOnline
                ? "Security gateway is responding"
                : "Backend connection unavailable"}
            </p>
          </div>

          <div className="profile">
            <div className="avatar">AG</div>
            <div>
              <strong>Security Admin</strong>
              <span>Administrator</span>
            </div>
            <ChevronDown size={16} />
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="breadcrumb-divider">/</span>
            <strong>{activeSection}</strong>
          </div>

          <div className="topbar-actions">
            <div className="environment">
              <span
                className={`status-dot ${backendOnline ? "" : "offline"}`}
              />
              {backendOnline ? "BACKEND CONNECTED" : "BACKEND OFFLINE"}
            </div>

            <button className="icon-button" aria-label="Search">
              <Search size={19} />
            </button>

            <button
              className="icon-button notification"
              aria-label="Notifications"
            >
              <Bell size={19} />
              {anomalyReport && anomalyReport.total_anomalies > 0 && <span />}
            </button>
          </div>
        </header>

        <div className="dashboard">
         
             {activeSection === "Agent Monitoring" ? (
  <div className="agent-monitoring-page">
    <section className="welcome-section">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          AUTONOMOUS AGENT OVERSIGHT
        </div>
        <h2>Agent Monitoring</h2>
        <p>
          Observe agent behavior, tool usage and security decisions
          recorded by AEGISGATE.
        </p>
      </div>

      <button
        className="primary-button"
        onClick={() => void loadDashboard()}
        disabled={loading}
      >
        <RefreshCw size={17} className={loading ? "spin" : ""} />
        Refresh Data
      </button>
    </section>

    <section className="metrics-grid">
      <article className="metric-card">
        <div className="metric-top">
          <span>Observed Agents</span>
          <div className="metric-icon cyan">
            <Bot size={19} />
          </div>
        </div>
        <div className="metric-value">{agentStats.length}</div>
        <div className="metric-footer">Agents in loaded audit events</div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Total Requests</span>
          <div className="metric-icon purple">
            <Activity size={19} />
          </div>
        </div>
        <div className="metric-value">
          {agentStats.reduce((sum, agent) => sum + agent.total, 0)}
        </div>
        <div className="metric-footer">Recorded agent activity</div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Blocked Requests</span>
          <div className="metric-icon red">
            <ShieldAlert size={19} />
          </div>
        </div>
        <div className="metric-value">
          {agentStats.reduce((sum, agent) => sum + agent.blocked, 0)}
        </div>
        <div className="metric-footer">Requests denied by policy</div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Tools Observed</span>
          <div className="metric-icon green">
            <Terminal size={19} />
          </div>
        </div>
        <div className="metric-value">
          {new Set(events.map((event) => event.tool_name)).size}
        </div>
        <div className="metric-footer">Distinct tools in audit records</div>
      </article>
    </section>

    <section className="panel events-panel">
      <div className="panel-header">
        <div>
          <h3>Registered Agent Activity</h3>
          <p>
            Agent identities discovered from recorded security events
          </p>
        </div>
        <span className="event-count">
          {agentStats.length} AGENTS OBSERVED
        </span>
      </div>

      {agentStats.length > 0 ? (
        <div className="agent-list">
          {agentStats.map((agent) => (
            <article className="agent-card" key={agent.agentId}>
              <div className="agent-card-header">
                <div className="agent-identity">
                  <div className="agent-avatar">
                    <Bot size={23} />
                  </div>
                  <div>
                    <h3>{agent.agentId}</h3>
                    <span>
                      {agent.tools.size} distinct tools observed
                    </span>
                  </div>
                </div>

                <span className="agent-status">
                  <span className="status-dot" />
                  OBSERVED
                </span>
              </div>

              <div className="agent-stat-grid">
                <div>
                  <span>Total Requests</span>
                  <strong>{agent.total}</strong>
                </div>
                <div>
                  <span>Allowed</span>
                  <strong className="success-text">
                    {agent.allowed}
                  </strong>
                </div>
                <div>
                  <span>Blocked</span>
                  <strong className="danger-text">
                    {agent.blocked}
                  </strong>
                </div>
                <div>
                  <span>Approval Required</span>
                  <strong>{agent.approval}</strong>
                </div>
              </div>

              <div className="agent-tools">
                <span>OBSERVED TOOLS</span>
                <div>
                  {Array.from(agent.tools).map((tool) => (
                    <span className="tool-chip" key={tool}>
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              <div className="agent-last-seen">
                <Clock3 size={14} />
                Last recorded activity: {formatTimestamp(agent.lastSeen)}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-events">
          <Bot size={24} />
          <span>
            {loading
              ? "Loading agent activity..."
              : "No agent activity has been recorded yet."}
          </span>
        </div>
      )}
    </section>
  </div>
) : activeSection === "Threat Detection" ? (
  <div className="threat-detection-page">
    <section className="welcome-section">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          BEHAVIORAL THREAT INTELLIGENCE
        </div>
        <h2>Threat Detection</h2>
        <p>Identify suspicious agent behavior and investigate anomalies detected by AEGISGATE.</p>
      </div>
      <button className="primary-button" onClick={() => void loadDashboard()} disabled={loading}>
        <RefreshCw size={17} className={loading ? "spin" : ""} />
        {loading ? "Refreshing..." : "Refresh Data"}
      </button>
    </section>

    <section className="metrics-grid">
      <article className="metric-card">
        <div className="metric-top"><span>Total Anomalies</span><div className="metric-icon purple"><ShieldAlert size={19} /></div></div>
        <div className="metric-value">{anomalyReport?.total_anomalies ?? "—"}</div>
        <div className="metric-footer">Detected behavioral anomalies</div>
      </article>
      <article className="metric-card">
        <div className="metric-top"><span>High Severity</span><div className="metric-icon red"><CircleAlert size={19} /></div></div>
        <div className="metric-value danger-text">{highAnomalyCount}</div>
        <div className="metric-footer">Requires immediate investigation</div>
      </article>
      <article className="metric-card">
        <div className="metric-top"><span>Medium Severity</span><div className="metric-icon purple"><Activity size={19} /></div></div>
        <div className="metric-value">{mediumAnomalyCount}</div>
        <div className="metric-footer">Suspicious behavioral patterns</div>
      </article>
      <article className="metric-card">
        <div className="metric-top"><span>Events Analyzed</span><div className="metric-icon cyan"><ScrollText size={19} /></div></div>
        <div className="metric-value">{anomalyReport?.events_analyzed ?? "—"}</div>
        <div className="metric-footer">Last {anomalyReport?.monitoring_window_seconds ?? 60} seconds</div>
      </article>
    </section>

    <section className="panel events-panel">
      <div className="panel-header">
        <div><h3>Detected Security Anomalies</h3><p>Behavioral patterns identified by the AEGISGATE detection engine</p></div>
        <span className="event-count">{anomalyReport?.total_anomalies ?? 0} ALERTS DETECTED</span>
      </div>

      {anomalyReport?.anomalies.length ? (
        <div className="threat-list">
          {anomalyReport.anomalies.map((anomaly, index) => (
            <article className="threat-card" key={`${anomaly.agent_id}-${anomaly.anomaly_type}-${index}`}>
              <div className="threat-card-header">
                <div className="threat-card-title">
                  <div className="threat-alert-icon"><ShieldAlert size={21} /></div>
                  <div><h3>{anomaly.anomaly_type.replaceAll("_", " ")}</h3><span>Agent: {anomaly.agent_id}</span></div>
                </div>
                <span className={`severity ${anomaly.severity.toLowerCase()}`}>{anomaly.severity}</span>
              </div>
              <p className="threat-explanation">{anomaly.explanation}</p>
              <div className="threat-details">
                <div><span>Observed Events</span><strong>{anomaly.count}</strong></div>
                <div><span>Detection Threshold</span><strong>{anomaly.threshold}</strong></div>
                <div><span>Severity</span><strong>{anomaly.severity}</strong></div>
              </div>
              <div className="threat-evidence">
                <span>RELATED FORENSIC EVENT IDS</span>
                <div>{anomaly.event_ids.map((eventId) => <code key={eventId}>{eventId.slice(0, 8)}</code>)}</div>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-events">
          <CircleCheck size={24} />
          <span>{loading ? "Analyzing agent behavior..." : "No anomalies detected in the current monitoring window."}</span>
        </div>
            )}
    </section>
    </div>
) : activeSection === "Security Events" ? (
  <div className="security-events-page">
    <section className="welcome-section">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          DIGITAL FORENSICS & AUDIT
        </div>
        <h2>Security Events</h2>
        <p>
          Search, filter and investigate security decisions recorded by
          the AEGISGATE runtime security engine.
        </p>
      </div>

      <button
        className="primary-button"
        onClick={() => void loadDashboard()}
        disabled={loading}
      >
        <RefreshCw size={17} className={loading ? "spin" : ""} />
        Refresh Data
      </button>
    </section>

    <section className="metrics-grid">
      {[
        { label: "Total Events", value: decisionCounts.ALL, color: "cyan" },
        { label: "Allowed", value: decisionCounts.ALLOW, color: "green" },
        { label: "Blocked", value: decisionCounts.BLOCK, color: "red" },
        {
          label: "Approval Required",
          value: decisionCounts.REQUIRE_APPROVAL,
          color: "purple",
        },
      ].map((metric) => (
        <article className="metric-card" key={metric.label}>
          <div className="metric-top">
            <span>{metric.label}</span>
            <div className={`metric-icon ${metric.color}`}>
              <ScrollText size={19} />
            </div>
          </div>
          <div className="metric-value">{metric.value}</div>
          <div className="metric-footer">Recorded security decisions</div>
        </article>
      ))}
    </section>

    <section className="panel events-panel">
      <div className="panel-header">
        <div>
          <h3>Forensic Event Explorer</h3>
          <p>Investigate recorded agent activity and security decisions</p>
        </div>
        <span className="event-count">
          {filteredEvents.length} EVENTS FOUND
        </span>
      </div>

      <div className="event-controls">
        <div className="event-search">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search agent, tool, operation or event ID..."
            value={eventSearch}
            onChange={(e) => setEventSearch(e.target.value)}
          />
          {eventSearch && (
            <button
              className="clear-search"
              onClick={() => setEventSearch("")}
              aria-label="Clear search"
            >
              <XCircle size={17} />
            </button>
          )}
        </div>

        <div className="event-filters">
          {(["ALL", "ALLOW", "BLOCK", "REQUIRE_APPROVAL"] as const).map(
            (filter) => (
              <button
                key={filter}
                className={`event-filter ${
                  decisionFilter === filter ? "active" : ""
                }`}
                onClick={() => setDecisionFilter(filter)}
              >
                {filter === "REQUIRE_APPROVAL"
                  ? "REQUIRES APPROVAL"
                  : filter}
                <span>{decisionCounts[filter]}</span>
              </button>
            )
          )}
        </div>
      </div>

      {filteredEvents.length > 0 ? (
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>EVENT ID</th>
                <th>AGENT</th>
                <th>TOOL / OPERATION</th>
                <th>DECISION</th>
                <th>EXECUTION</th>
                <th>TIMESTAMP</th>
                <th>INVESTIGATE</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((event) => (
                <tr key={event.event_id}>
                  <td>
                    <span className="event-id">
                      {event.event_id.slice(0, 8)}
                    </span>
                  </td>
                  <td>{event.agent_id}</td>
                  <td>
                    <strong>{event.tool_name}</strong>
                    <span className="table-subtext">{event.operation}</span>
                  </td>
                  <td>
                    <span
                      className={`decision-badge ${event.decision.toLowerCase()}`}
                    >
                      {event.decision.replaceAll("_", " ")}
                    </span>
                  </td>
                  <td>
                    {event.executed ? (
                      <span className="execution-success">
                        <CircleCheck size={14} /> Executed
                      </span>
                    ) : (
                      <span className="execution-blocked">
                        <XCircle size={14} /> Not executed
                      </span>
                    )}
                  </td>
                  <td className="timestamp-cell">
                    <Clock3 size={13} />
                    {formatTimestamp(event.timestamp)}
                  </td>
                  <td>
                    <button
                      className="inspect-event-button"
                      onClick={() => setSelectedEvent(event)}
                    >
                      Inspect <ArrowUpRight size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-events">
          <Search size={23} />
          <span>
            {loading
              ? "Loading security events..."
              : "No matching security events found."}
          </span>
        </div>
      )}
    </section>

    {selectedEvent && (
      <section
  ref={detailPanelRef}
  className="panel event-detail-panel"
>
        <div className="panel-header">
          <div>
            <h3>Forensic Event Details</h3>
            <p>Detailed evidence for the selected security event</p>
          </div>
          <button
            className="icon-button"
            onClick={() => setSelectedEvent(null)}
            aria-label="Close event details"
          >
            <XCircle size={19} />
          </button>
        </div>

        <div className="event-detail-grid">
          <div>
            <span>EVENT ID</span>
            <strong>{selectedEvent.event_id}</strong>
          </div>
          <div>
            <span>AGENT ID</span>
            <strong>{selectedEvent.agent_id}</strong>
          </div>
          <div>
            <span>TOOL</span>
            <strong>{selectedEvent.tool_name}</strong>
          </div>
          <div>
            <span>OPERATION</span>
            <strong>{selectedEvent.operation}</strong>
          </div>
          <div>
            <span>RESOURCE</span>
            <strong>{selectedEvent.resource ?? "Not specified"}</strong>
          </div>
          <div>
            <span>DECISION</span>
            <strong>{selectedEvent.decision.replaceAll("_", " ")}</strong>
          </div>
	  <div className="event-reason">
            <span>DECISION REASON</span>
            <strong>{selectedEvent.reason || "No reason recorded"}</strong>
          </div>

          <div>
            <span>EXECUTION STATUS</span>
            <strong>{selectedEvent.executed ? "Executed" : "Not executed"}</strong>
          </div>
          <div>
            <span>TIMESTAMP</span>
            <strong>{formatTimestamp(selectedEvent.timestamp)}</strong>
          </div>
        </div>

        <div className="forensic-hashes">
          <h4>HASH-CHAIN EVIDENCE</h4>
          <div>
            <span>Previous Hash</span>
            <code>{selectedEvent.previous_hash ?? "No previous hash"}</code>
          </div>
          <div>
            <span>Event Hash</span>
            <code>{selectedEvent.event_hash ?? "Not available"}</code>
          </div>
        </div>
      </section>
    )}
    </div>
) : activeSection === "Integrity Verification" ? (
  <div className="integrity-verification-page">
    <section className="welcome-section">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          DIGITAL FORENSICS & DATA INTEGRITY
        </div>
        <h2>Integrity Verification</h2>
        <p>
          Verify the integrity of security audit records and detect
          unauthorized modifications to the forensic hash chain.
        </p>
      </div>

      <button
        className="primary-button"
        onClick={() => void loadDashboard()}
        disabled={loading}
      >
        <RefreshCw size={17} className={loading ? "spin" : ""} />
        {loading ? "Verifying..." : "Run Verification"}
      </button>
    </section>

    {error && (
      <div className="connection-error">
        <CircleAlert size={18} />
        <div>
          <strong>Unable to retrieve verification results</strong>
          <p>{error}</p>
        </div>
        <button onClick={() => void loadDashboard()}>Retry</button>
      </div>
    )}

    <section className="integrity-status-banner">
      <div className="integrity-icon">
        {integrity?.valid ? (
          <CircleCheck size={28} />
        ) : (
          <CircleAlert size={28} />
        )}
      </div>

      <div className="integrity-info">
        <strong>
          {loading
            ? "Verification in progress..."
            : integrity
              ? integrity.valid
                ? "Hash Chain Integrity Verified"
                : "Hash Chain Verification Failed"
              : "Waiting for verification"}
        </strong>
        <span>
          {integrity?.reason ??
            "Run verification to inspect the integrity of recorded security events."}
        </span>
      </div>

      <div
        className={`integrity-result ${
          integrity?.valid ? "verified" : "failed"
        }`}
      >
        {integrity?.valid ? (
          <CircleCheck size={17} />
        ) : (
          <CircleAlert size={17} />
        )}
        {integrity
          ? integrity.valid
            ? "HASH CHAIN VALID"
            : "VERIFICATION FAILED"
          : "NOT CHECKED"}
      </div>
    </section>

    <section className="metrics-grid">
      <article className="metric-card">
        <div className="metric-top">
          <span>Verified Events</span>
          <div className="metric-icon green">
            <Fingerprint size={19} />
          </div>
        </div>
        <div className="metric-value">
          {loading ? "..." : integrity?.checked_events ?? "—"}
        </div>
        <div className="metric-footer">
          Events checked through hash-chain verification
        </div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Legacy Events</span>
          <div className="metric-icon purple">
            <ScrollText size={19} />
          </div>
        </div>
        <div className="metric-value">
          {loading ? "..." : integrity?.legacy_events ?? "—"}
        </div>
        <div className="metric-footer">
          Records not covered by cryptographic verification
        </div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Verification Result</span>
          <div className={`metric-icon ${integrity?.valid ? "green" : "red"}`}>
            {integrity?.valid ? (
              <CircleCheck size={19} />
            ) : (
              <CircleAlert size={19} />
            )}
          </div>
        </div>
        <div className="metric-value">
          {loading ? "..." : integrity ? (integrity.valid ? "Valid" : "Failed") : "—"}
        </div>
        <div className="metric-footer">
          Current audit hash-chain status
        </div>
      </article>

      <article className="metric-card">
        <div className="metric-top">
          <span>Legacy Coverage</span>
          <div className="metric-icon cyan">
            <Shield size={19} />
          </div>
        </div>
        <div className="metric-value">
          {loading
            ? "..."
            : integrity
              ? integrity.legacy_events_verified
                ? "Covered"
                : "Excluded"
              : "—"}
        </div>
        <div className="metric-footer">
          Cryptographic coverage of legacy records
        </div>
      </article>
    </section>

    <section className="panel integrity-details-panel">
      <div className="panel-header">
        <div>
          <h3>Verification Details</h3>
          <p>Results returned by the AEGISGATE integrity engine</p>
        </div>
        <Fingerprint size={20} className="muted-icon" />
      </div>

      {integrity ? (
        <div className="integrity-detail-list">
          <div>
            <span>Hash Chain Status</span>
            <strong className={integrity.valid ? "success-text" : "danger-text"}>
              {integrity.valid ? "Valid" : "Invalid"}
            </strong>
          </div>

          <div>
            <span>Events Hash-Checked</span>
            <strong>{integrity.checked_events}</strong>
          </div>

          <div>
            <span>Legacy Events</span>
            <strong>{integrity.legacy_events}</strong>
          </div>

          <div>
            <span>Legacy Events Cryptographically Verified</span>
            <strong>
              {integrity.legacy_events_verified ? "Yes" : "No"}
            </strong>
          </div>

          <div>
            <span>Failed Event ID</span>
            <strong className="integrity-event-id">
              {integrity.failed_event_id ?? "None"}
            </strong>
          </div>

          <div>
            <span>Verification Explanation</span>
            <strong>{integrity.reason}</strong>
          </div>
        </div>
      ) : (
        <div className="empty-events">
          <Fingerprint size={23} />
          <span>
            {loading
              ? "Checking audit record integrity..."
              : "No verification report available."}
          </span>
        </div>
      )}
    </section>

    <section className="integrity-explanation">
      <div className="integrity-explanation-icon">
        <LockKeyhole size={21} />
      </div>
      <div>
        <h3>Understanding Hash-Chain Verification</h3>
        <p>
          AEGISGATE links audit records using cryptographic hashes.
          Each hashed event contains evidence connected to the previous
          event. If a covered record is modified, the verification
          process can detect an integrity failure.
        </p>
        <p>
          Legacy events were recorded before hash-chain protection
          was introduced. They are not covered by cryptographic
          integrity verification and should not be treated as
          verified records.
        </p>
      </div>
    </section>

    <footer className="dashboard-footer">
      <span>AEGISGATE SECURITY PLATFORM</span>
      <span>
        Runtime Protection · Behavioral Analysis · Digital Forensics
      </span>
      <span>
        {lastUpdated
          ? `Updated ${lastUpdated.toLocaleTimeString()}`
          : "Waiting for data"}
      </span>
    </footer>
    </div>
) : activeSection === "Tool Activity" ? (
  <div className="tool-activity-page">
    <section className="welcome-section">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          SECURITY OPERATIONS CENTER
        </div>

        <h2>Tool Activity</h2>
        <p>
          Monitor tool usage. Track operations. Control every AI agent action.
        </p>
      </div>

      <button
        className="primary-button"
        onClick={() => void loadDashboard()}
        disabled={loading}
      >
        <RefreshCw size={17} className={loading ? "spin" : ""} />
        {loading ? "Refreshing..." : "Refresh Data"}
        <span className="live-indicator" />
      </button>
    </section>

    {error && (
      <div className="connection-error">
        <CircleAlert size={18} />
        <div>
          <strong>Unable to load tool activity</strong>
          <p>{error}</p>
        </div>
      </div>
    )}

    <section className="stats-grid">
      <div className="stat-card">
        <span className="stat-label">Total Tool Requests</span>
        <strong className="stat-value">{events.length}</strong>
        <span className="stat-description">Loaded security events</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Tools Detected</span>
        <strong className="stat-value">{toolStats.length}</strong>
        <span className="stat-description">Unique tools in event records</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Blocked Requests</span>
        <strong className="stat-value">{blockedCount}</strong>
        <span className="stat-description">Requests denied by policy</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Approval Required</span>
        <strong className="stat-value">{approvalCount}</strong>
<span className="stat-description">Requests requiring approval</span>
      </div>
    </section>

    <section className="panel tool-activity-panel">
      <div className="panel-header">
        <div>
          <h3>Tool Usage Overview</h3>
          <p>Activity grouped by tool name</p>
        </div>
        <span className="live-badge">LIVE DATA</span>
      </div>

      {toolStats.length > 0 ? (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>TOOL</th>
                <th>REQUESTS</th>
                <th>ALLOWED</th>
                <th>BLOCKED</th>
                <th>APPROVAL</th>
                <th>EXECUTED</th>
                <th>OPERATIONS</th>
              </tr>
            </thead>
            <tbody>
              {toolStats.map((tool) => (
                <tr key={tool.toolName}>
                  <td><strong>{tool.toolName}</strong></td>
                  <td>{tool.total}</td>
                  <td>{tool.allowed}</td>
                  <td>{tool.blocked}</td>
                  <td>{tool.approval}</td>
                  <td>{tool.executed}</td>
                  <td>{Array.from(tool.operations).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <Terminal size={28} />
          <h3>No tool activity available</h3>
          <p>Security events will appear here when agents perform tool requests.</p>
        </div>
      )}
    </section>

    <section className="panel tool-activity-panel">
      <div className="panel-header">
        <div>
          <h3>Recent Tool Operations</h3>
          <p>Latest actions recorded by the security engine</p>
        </div>
        <span className="live-badge">{events.length} EVENTS</span>
      </div>

      {events.length > 0 ? (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>AGENT</th>
                <th>TOOL</th>
                <th>OPERATION</th>
                <th>DECISION</th>
                <th>EXECUTION</th>
                <th>TIMESTAMP</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 10).map((event) => (
                <tr key={event.event_id}>
                  <td>{event.agent_id}</td>
                  <td><strong>{event.tool_name}</strong></td>
                  <td>{event.operation}</td>
                  <td>
  <span className={`decision-badge ${event.decision.toLowerCase()}`}>
    {event.decision}
  </span>
</td>
<td>
  <span className={event.executed ? "execution-success" : "execution-blocked"}>
    {event.executed ? "Executed" : "Not executed"}
  </span>
</td>
                  <td>{new Date(event.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <p>No recent tool operations recorded.</p>
        </div>
      )}
    </section>

    <footer className="dashboard-footer">
      <span>AEGISGATE SECURITY PLATFORM</span>
      <span>
        Runtime Protection · Behavioral Analysis · Digital Forensics
      </span>
      <span>
        {lastUpdated
          ? `Updated ${lastUpdated.toLocaleTimeString()}`
          : "Waiting for data"}
      </span>
    </footer>
  </div>
) : (
  <>
          <section className="welcome-section">

            <div>
              <div className="eyebrow">
                <span className="eyebrow-line" />
                SECURITY OPERATIONS CENTER
              </div>

              <h2>
                 {activeSection === "Overview" ? "Security               Overview" : activeSection}
              </h2>

              <p>
                Monitor your AI agents. Detect threats. Protect every action.
              </p>
            </div>

            <button
              className="primary-button"
              onClick={() => void loadDashboard()}
              disabled={loading}
            >
              <RefreshCw size={17} className={loading ? "spin" : ""} />
              {loading ? "Refreshing..." : "Refresh Data"}
              <span className="live-indicator" />
            </button>
          </section>

          {error && (
            <div className="connection-error">
              <CircleAlert size={18} />
              <div>
                <strong>Unable to load dashboard data</strong>
                <p>{error}</p>
              </div>
              <button onClick={() => void loadDashboard()}>Retry</button>
            </div>
          )}

          <section className="metrics-grid">
            {metrics.map((metric) => {
              const Icon = metric.icon;

              return (
                <article className="metric-card" key={metric.label}>
                  <div className="metric-top">
                    <span>{metric.label}</span>
                    <div className={`metric-icon ${metric.color}`}>
                      <Icon size={19} />
                    </div>
                  </div>

                  <div className="metric-value">
                    {loading ? "..." : metric.value}
                  </div>

                  <div className="metric-footer">
                    <CircleCheck
                      size={14}
                      className={
                        metric.label === "Integrity Status" &&
                        integrity?.valid
                          ? "success-text"
                          : "muted-icon"
                      }
                    />
                    <span>{metric.detail}</span>
                  </div>
                </article>
              );
            })}
          </section>

          <section className="content-grid">
            <article className="panel activity-panel">
              <div className="panel-header">
                <div>
                  <h3>Security Activity</h3>
                  <p>Event decisions over the last 7 days</p>
                </div>

                <span className="chart-live-label">
                  <span className="status-dot" />
                  LIVE DATA
                </span>
              </div>

              <div className="chart-container">
                {events.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={chartData}
                      margin={{ top: 12, right: 12, left: -20, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient
                          id="allowedGradient"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="0%"
                            stopColor="#22d3ee"
                            stopOpacity={0.28}
                          />
                          <stop
                            offset="95%"
                            stopColor="#22d3ee"
                            stopOpacity={0}
                          />
                        </linearGradient>

                        <linearGradient
                          id="blockedGradient"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="0%"
                            stopColor="#fb7185"
                            stopOpacity={0.25}
                          />
                          <stop
                            offset="95%"
                            stopColor="#fb7185"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>

                      <CartesianGrid
                        stroke="#263449"
                        strokeDasharray="4 5"
                        vertical={false}
                      />

                      <XAxis
                        dataKey="date"
                        tick={{ fill: "#8292a9", fontSize: 12 }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <YAxis
                        allowDecimals={false}
                        tick={{ fill: "#8292a9", fontSize: 12 }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <Tooltip
                        contentStyle={{
                          background: "#111d30",
                          border: "1px solid #293b52",
                          borderRadius: "10px",
                          color: "#f1f5f9",
                        }}
                      />

                      <Area
                        type="monotone"
                        dataKey="allowed"
                        name="Allowed"
                        stroke="#22d3ee"
                        fill="url(#allowedGradient)"
                        strokeWidth={2}
                      />

                      <Area
                        type="monotone"
                        dataKey="blocked"
                        name="Blocked"
                        stroke="#fb7185"
                        fill="url(#blockedGradient)"
                        strokeWidth={2}
                      />

                      <Area
                        type="monotone"
                        dataKey="approval"
                        name="Requires approval"
                        stroke="#a78bfa"
                        fill="transparent"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="chart-placeholder">
                    <Activity size={26} />
                    <strong>No activity data available</strong>
                    <span>New audit events will appear here.</span>
                  </div>
                )}
              </div>

              <div className="activity-legend">
                <span><i className="legend-cyan" /> Allowed: {allowedCount}</span>
                <span><i className="legend-red" /> Blocked: {blockedCount}</span>
                <span><i className="legend-purple" /> Approval: {approvalCount}</span>
              </div>
            </article>

            <article className="panel threat-panel">
              <div className="panel-header">
                <div>
                  <h3>Threat Intelligence</h3>
                  <p>Behavioral security monitoring</p>
                </div>
                <ShieldAlert size={19} className="muted-icon" />
              </div>

              <div className="threat-summary">
                <div className="threat-shield">
                  {anomalyReport && anomalyReport.total_anomalies > 0 ? (
                    <ShieldAlert size={27} />
                  ) : (
                    <LockKeyhole size={27} />
                  )}
                </div>

                <div>
                  <strong>
                    {anomalyReport?.total_anomalies ?? "—"} anomalies
                  </strong>
                  <span>
                    {anomalyReport
                      ? `${anomalyReport.events_analyzed} events analyzed in the last ${anomalyReport.monitoring_window_seconds}s`
                      : "Waiting for analysis"}
                  </span>
                </div>
              </div>

              <div className="anomaly-list">
                {anomalyReport?.anomalies.length ? (
                  anomalyReport.anomalies.slice(0, 4).map((anomaly, index) => (
                    <div className="anomaly-item" key={`${anomaly.anomaly_type}-${index}`}>
                      <div className="anomaly-indicator">
                        <CircleAlert size={16} />
                      </div>
                      <div className="anomaly-info">
                        <strong>
                          {anomaly.anomaly_type.replaceAll("_", " ")}
                        </strong>
                        <span>
                          {anomaly.agent_id} · {anomaly.count} events
                        </span>
                      </div>
                      <span
                        className={`severity ${anomaly.severity.toLowerCase()}`}
                      >
                        {anomaly.severity}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="no-threats">
                    <CircleCheck size={17} />
                    <span>No anomalies detected in the monitoring window.</span>
                  </div>
                )}
              </div>
            </article>
          </section>

          <section className="panel events-panel">
            <div className="panel-header">
              <div>
                <h3>Recent Security Events</h3>
                <p>Latest activity recorded by the security engine</p>
              </div>

              <span className="event-count">
                {events.length} EVENTS LOADED
              </span>
            </div>

            {events.length > 0 ? (
              <div className="events-table-wrapper">
                <table className="events-table">
                  <thead>
                    <tr>
                      <th>EVENT</th>
                      <th>AGENT</th>
                      <th>TOOL / OPERATION</th>
                      <th>DECISION</th>
                      <th>EXECUTION</th>
                      <th>TIMESTAMP</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.slice(0, 7).map((event) => (
                      <tr key={event.event_id}>
                        <td>
                          <span className="event-id">
                            {event.event_id.slice(0, 8)}
                          </span>
                        </td>

                        <td>{event.agent_id}</td>

                        <td>
                          <strong>{event.tool_name}</strong>
                          <span className="table-subtext">
                            {event.operation}
                          </span>
                        </td>

                        <td>
                          <span
                            className={`decision-badge ${event.decision.toLowerCase()}`}
                          >
                            {event.decision.replaceAll("_", " ")}
                          </span>
                        </td>

                        <td>
                          {event.executed ? (
                            <span className="execution-success">
                              <CircleCheck size={14} /> Executed
                            </span>
                          ) : (
                            <span className="execution-blocked">
                              <XCircle size={14} /> Not executed
                            </span>
                          )}
                        </td>

                        <td className="timestamp-cell">
                          <Clock3 size={13} />
                          {formatTimestamp(event.timestamp)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-events">
                <ScrollText size={22} />
                <span>
                  {loading
                    ? "Loading security events..."
                    : "No security events have been recorded yet."}
                </span>
              </div>
            )}
          </section>

          <section className="integrity-panel">
            <div className="integrity-icon">
              <Fingerprint size={23} />
            </div>

            <div className="integrity-info">
              <strong>Forensic Integrity Verification</strong>
              <span>
                {integrity
                  ? integrity.reason
                  : "Waiting for integrity verification"}
              </span>
            </div>

            <div
              className={`integrity-result ${
                integrity?.valid ? "verified" : "failed"
              }`}
            >
              {integrity ? (
                integrity.valid ? (
                  <CircleCheck size={17} />
                ) : (
                  <CircleAlert size={17} />
                )
              ) : null}
              {integrity
                ? integrity.valid
                  ? "HASH CHAIN VALID"
                  : "VERIFICATION FAILED"
                : "NOT CHECKED"}
            </div>
          </section>

          <footer className="dashboard-footer">
            <span>AEGISGATE SECURITY PLATFORM</span>
            <span>
              Runtime Protection · Behavioral Analysis · Digital Forensics
            </span>
            <span>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : "Waiting for data"}
            </span>
          </footer>

          </>
        )}
        </div>
      </main>
    </div>
  );
}

export default App;