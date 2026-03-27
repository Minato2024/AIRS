import { Suspense, lazy, startTransition, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Ban,
  Clock3,
  Eye,
  Moon,
  Radar,
  RefreshCcw,
  Server,
  Settings2,
  Shield,
  Sparkles,
  Sun,
  Target,
  TerminalSquare,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react'
import './App.css'

const API_ROOT = '/api/v1'
const ThreatTimelineChart = lazy(() => import('./components/ThreatTimelineChart.jsx'))

const menuItems = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'threats', label: 'Threats', icon: AlertTriangle },
  { id: 'honeypot', label: 'Honeypot', icon: TerminalSquare },
  { id: 'response', label: 'Response', icon: Zap },
  { id: 'settings', label: 'Settings', icon: Settings2 },
]

function formatPercent(value) {
  return `${((value ?? 0) * 100).toFixed(1)}%`
}

function formatAbsolutePercent(value) {
  return `${Number(value ?? 0).toFixed(0)}%`
}

function formatTimestamp(value) {
  if (!value) return 'No timestamp'

  return new Date(value).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function formatUtcPlusOneTime(value) {
  if (!value) return 'No time'

  return new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'Africa/Lagos',
  }).format(new Date(value))
}

function labelize(value) {
  if (!value) return 'Unknown'

  return String(value)
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())
}

async function fetchJson(path, options) {
  const response = await fetch(`${API_ROOT}${path}`, options)

  if (!response.ok) {
    let message = `Request failed for ${path}`

    try {
      const payload = await response.json()
      message = payload.detail || payload.message || message
    } catch {
      // Keep fallback error message.
    }

    throw new Error(message)
  }

  return response.json()
}

function App() {
  const [activeTab, setActiveTab] = useState('overview')
  const [darkMode, setDarkMode] = useState(false)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [errors, setErrors] = useState([])
  const [flashMessage, setFlashMessage] = useState('')
  const [socketMessages, setSocketMessages] = useState([])

  const [stats, setStats] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [mitre, setMitre] = useState(null)
  const [health, setHealth] = useState(null)
  const [detectionStats, setDetectionStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [selectedThreatId, setSelectedThreatId] = useState(null)
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [threatUpdateBusy, setThreatUpdateBusy] = useState(false)
  const [honeypotSessions, setHoneypotSessions] = useState([])
  const [blockedIps, setBlockedIps] = useState([])
  const [responseActions, setResponseActions] = useState([])
  const [responseSettings, setResponseSettings] = useState(null)
  const [settingsDraft, setSettingsDraft] = useState({
    auto_response_enabled: true,
    response_cooldown_seconds: 300,
  })
  const [settingsBusy, setSettingsBusy] = useState(false)
  const refreshTimeoutRef = useRef(null)

  const timelineData = useMemo(
    () =>
      timeline.map((item) => ({
        time: formatUtcPlusOneTime(item.timestamp),
        threats: item.value,
        timestamp: item.timestamp,
      })),
    [timeline],
  )

  async function loadOverviewData() {
    const [statsData, timelineResponse, mitreData, healthData] = await Promise.all([
      fetchJson('/dashboard/stats'),
      fetchJson('/dashboard/timeline?hours=24&interval=hour'),
      fetchJson('/dashboard/mitre-coverage'),
      fetchJson('/dashboard/system-health'),
    ])

    setStats(statsData)
    setTimeline(timelineResponse)
    setMitre(mitreData)
    setHealth(healthData)
  }

  async function loadThreatData() {
    const [statsData, threatsData] = await Promise.all([
      fetchJson('/detection/stats?hours=24'),
      fetchJson('/detection/threats?limit=20'),
    ])

    const nextThreats = threatsData.threats ?? []
    setDetectionStats(statsData)
    setThreats(nextThreats)

    if (!selectedThreatId && nextThreats.length > 0) {
      setSelectedThreatId(nextThreats[0].id)
    }
  }

  async function loadHoneypotData() {
    const sessionData = await fetchJson('/honeypot/sessions?hours=24&limit=20')
    setHoneypotSessions(sessionData.sessions ?? [])
  }

  async function loadResponseData() {
    const [blockedData, actionsData, settingsData] = await Promise.all([
      fetchJson('/response/blocked-ips?limit=20'),
      fetchJson('/response/actions?limit=20'),
      fetchJson('/response/settings'),
    ])

    setBlockedIps(blockedData.blocked_ips ?? [])
    setResponseActions(actionsData.actions ?? [])
    setResponseSettings(settingsData)
    setSettingsDraft({
      auto_response_enabled: settingsData.auto_response_enabled,
      response_cooldown_seconds: settingsData.response_cooldown_seconds,
    })
  }

  async function loadAllData({ silent = false } = {}) {
    if (silent) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }

    setErrors([])

    try {
      await Promise.all([
        loadOverviewData(),
        loadThreatData(),
        loadHoneypotData(),
        loadResponseData(),
      ])
    } catch (error) {
      setErrors((previous) => [...previous, error.message || 'Unable to load AIRS data'])
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  async function loadThreatDetail(threatId) {
    try {
      const detail = await fetchJson(`/detection/threats/${threatId}`)
      setSelectedThreat(detail)
    } catch (error) {
      setErrors((previous) => [...previous, error.message || 'Unable to load threat detail'])
    }
  }

  async function handleThreatStatusUpdate(threatId, status) {
    setThreatUpdateBusy(true)

    try {
      await fetchJson(`/detection/threats/${threatId}/status?status=${encodeURIComponent(status)}`, {
        method: 'PATCH',
      })
      setFlashMessage(`Threat #${threatId} updated to ${labelize(status)}.`)
      await loadThreatData()
      await loadThreatDetail(threatId)
    } catch (error) {
      setErrors((previous) => [...previous, error.message || 'Unable to update threat status'])
    } finally {
      setThreatUpdateBusy(false)
    }
  }

  async function handleUnblock(ipAddress) {
    try {
      await fetchJson(`/response/unblock-ip/${encodeURIComponent(ipAddress)}`, {
        method: 'POST',
      })
      setFlashMessage(`${ipAddress} was unblocked successfully.`)
      await loadResponseData()
      await loadOverviewData()
    } catch (error) {
      setErrors((previous) => [...previous, error.message || 'Unable to unblock IP'])
    }
  }

  async function handleSettingsSave(event) {
    event.preventDefault()
    setSettingsBusy(true)

    const params = new URLSearchParams({
      auto_response_enabled: String(settingsDraft.auto_response_enabled),
      response_cooldown_seconds: String(settingsDraft.response_cooldown_seconds),
    })

    try {
      const updated = await fetchJson(`/response/settings?${params.toString()}`, {
        method: 'PUT',
      })
      setResponseSettings((previous) => ({
        ...previous,
        ...updated,
        anomaly_threshold: previous?.anomaly_threshold,
        confidence_threshold: previous?.confidence_threshold,
      }))
      setFlashMessage('Response settings saved.')
    } catch (error) {
      setErrors((previous) => [...previous, error.message || 'Unable to save settings'])
    } finally {
      setSettingsBusy(false)
    }
  }

  useEffect(() => {
    loadAllData()
  }, [])

  useEffect(() => {
    if (selectedThreatId) {
      loadThreatDetail(selectedThreatId)
    }
  }, [selectedThreatId])

  useEffect(() => {
    if (!flashMessage) return undefined

    const timer = setTimeout(() => setFlashMessage(''), 4000)
    return () => clearTimeout(timer)
  }, [flashMessage])

  useEffect(() => {
    let ws
    let reconnectTimer

    const scheduleRealtimeRefresh = () => {
      if (refreshTimeoutRef.current) return

      refreshTimeoutRef.current = setTimeout(() => {
        refreshTimeoutRef.current = null
        loadAllData({ silent: true })
      }, 600)
    }

    const connectWs = () => {
      const backendHost = window.location.hostname || 'localhost'
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${wsProtocol}//${backendHost}:8000/api/v1/dashboard/ws`

      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setSocketMessages((messages) => [
          ...messages,
          { type: 'system', text: 'Live channel connected' },
        ])
        ws.send('subscribe')
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setSocketMessages((messages) => [
            ...messages,
            { type: data.type || 'message', text: JSON.stringify(data) },
          ])

          if (
            ['new_threat', 'stats_update', 'pipeline_event', 'response_updated', 'settings_updated', 'threat_status_changed'].includes(
              data.type,
            )
          ) {
            scheduleRealtimeRefresh()
          }
        } catch {
          setSocketMessages((messages) => [
            ...messages,
            { type: 'message', text: event.data },
          ])
        }
      }

      ws.onerror = () => {
        setSocketMessages((messages) => [
          ...messages,
          { type: 'error', text: 'Live channel error detected' },
        ])
      }

      ws.onclose = () => {
        setSocketMessages((messages) => [
          ...messages,
          { type: 'system', text: 'Live channel closed. Reconnecting in 3 seconds.' },
        ])
        reconnectTimer = setTimeout(connectWs, 3000)
      }
    }

    connectWs()

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current)
      if (ws) ws.close()
    }
  }, [])

  const backendHealthy = health?.status === 'healthy'
  const recentAlerts = stats?.recent_alerts?.slice(0, 6) ?? []
  const latestAlert = recentAlerts[0]
  const liveMessages = socketMessages.slice(-6).reverse()
  const threatPressure =
    stats?.total_sessions_24h && stats?.active_threats
      ? Math.round((stats.active_threats / stats.total_sessions_24h) * 100)
      : 0

  const overviewCards = [
    {
      label: 'Total Sessions',
      value: stats?.total_sessions_24h ?? '--',
      detail: 'Observed across the last 24 hours',
      icon: Eye,
      tone: 'neutral',
    },
    {
      label: 'Active Threats',
      value: stats?.active_threats ?? '--',
      detail: `${threatPressure}% of tracked sessions currently flagged`,
      icon: AlertTriangle,
      tone: 'warning',
    },
    {
      label: 'Blocked IPs',
      value: stats?.blocked_ips ?? '--',
      detail: 'Containment actions currently active',
      icon: Ban,
      tone: 'danger',
    },
    {
      label: 'Detection Accuracy',
      value: formatPercent(stats?.detection_accuracy_7d),
      detail: 'Rolling seven-day confidence average',
      icon: Target,
      tone: 'success',
    },
  ]

  function renderActiveTab() {
    if (loading) {
      return <div className="message">Loading AIRS data surfaces...</div>
    }

    if (activeTab === 'overview') {
      return (
        <>
          <section className="hero-panel">
            <div className="hero-copy">
              <p className="eyebrow">Security Command Center</p>
              <h1>See the threat picture before it turns into incident backlog.</h1>
              <p className="hero-text">
                AIRS brings telemetry, detections, system state, and live event activity together so operators can spot changes quickly and respond with confidence.
              </p>
            </div>
            <div className="hero-rail">
              <div className="hero-toolbar">
                <div className={`status-chip ${backendHealthy ? 'healthy' : 'degraded'}`}>
                  <span className="status-icon">{backendHealthy ? <Wifi size={14} /> : <WifiOff size={14} />}</span>
                  <span>Backend {health?.status ?? 'unknown'}</span>
                </div>
                <button
                  className="refresh-icon-button"
                  onClick={() => loadAllData({ silent: true })}
                  aria-label={refreshing ? 'Refreshing data' : 'Refresh data'}
                  title={refreshing ? 'Refreshing data' : 'Refresh data'}
                >
                  <RefreshCcw size={16} className={refreshing ? 'spin' : ''} />
                </button>
              </div>
              <div className="hero-grid">
                <div className="highlight-card accent">
                  <div className="highlight-header">
                    <Radar size={18} />
                    <span>Threat Pressure</span>
                  </div>
                  <strong>{threatPressure}%</strong>
                  <p>Active threats compared to all sessions seen in the last 24 hours.</p>
                </div>
                <div className="highlight-card">
                  <div className="highlight-header">
                    <Clock3 size={18} />
                    <span>Latest Alert</span>
                  </div>
                  <strong>{latestAlert ? labelize(latestAlert.threat_level) : 'No alerts'}</strong>
                  <p>{latestAlert ? `${formatTimestamp(latestAlert.timestamp)} from ${latestAlert.source_ip}` : 'No recent alert activity was returned.'}</p>
                </div>
              </div>
            </div>
          </section>

          <section className="overview-grid">
            {overviewCards.map((card) => {
              const Icon = card.icon
              return (
                <article key={card.label} className={`overview-card tone-${card.tone}`}>
                  <div className="overview-icon">
                    <Icon size={20} />
                  </div>
                  <div>
                    <span className="card-label">{card.label}</span>
                    <strong className="card-value">{card.value}</strong>
                    <p className="card-detail">{card.detail}</p>
                  </div>
                </article>
              )
            })}
          </section>

          <section className="content-grid">
            <section className="panel panel-wide">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">Trendline</p>
                  <h3>Threat activity over the last 24 hours</h3>
                </div>
                <Sparkles size={18} />
              </div>
              <div className="chart-container">
                {timelineData.length === 0 ? (
                  <div className="empty-state">No timeline data available yet.</div>
                ) : (
                  <Suspense fallback={<div className="empty-state">Loading chart module...</div>}>
                    <ThreatTimelineChart data={timelineData} />
                  </Suspense>
                )}
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">Coverage</p>
                  <h3>MITRE ATT&CK visibility</h3>
                </div>
                <Target size={18} />
              </div>
              <div className="coverage-grid">
                <div className="coverage-cell">
                  <span>Tactics observed</span>
                  <strong>{mitre?.tactics_observed ?? 0}/{mitre?.total_tactics ?? 14}</strong>
                </div>
                <div className="coverage-cell">
                  <span>Techniques observed</span>
                  <strong>{mitre?.techniques_observed ?? 0}/{mitre?.total_techniques ?? 0}</strong>
                </div>
                <div className="coverage-cell coverage-cell-wide">
                  <span>Tactic coverage</span>
                  <strong>{formatAbsolutePercent(mitre?.tactic_coverage_percentage ?? mitre?.coverage_percentage)}</strong>
                </div>
              </div>
              <div className="meter">
                <div className="meter-fill" style={{ width: `${Number(mitre?.tactic_coverage_percentage ?? mitre?.coverage_percentage ?? 0)}%` }} />
              </div>
            </section>
          </section>

          <section className="content-grid secondary-grid">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">Alerts</p>
                  <h3>Recent detections</h3>
                </div>
                <AlertTriangle size={18} />
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Level</th>
                      <th>Type</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.length === 0 ? (
                      <tr><td colSpan="6" className="empty-table">No alerts returned yet.</td></tr>
                    ) : (
                      recentAlerts.map((alert) => (
                        <tr key={alert.id}>
                          <td className="mono-cell">#{alert.id}</td>
                          <td>{formatTimestamp(alert.timestamp)}</td>
                          <td className="mono-cell">{alert.source_ip}</td>
                          <td><span className={`badge level-${alert.threat_level.toLowerCase()}`}>{alert.threat_level}</span></td>
                          <td>{labelize(alert.attack_type)}</td>
                          <td><span className="badge badge-soft">{labelize(alert.status)}</span></td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">Live Feed</p>
                  <h3>WebSocket event stream</h3>
                </div>
                <Activity size={18} />
              </div>
              <div className="feed-list">
                {liveMessages.length === 0 ? (
                  <div className="empty-state">Waiting for live events from the backend.</div>
                ) : (
                  liveMessages.map((message, index) => (
                    <div key={`${message.type}-${index}`} className={`feed-entry feed-${message.type}`}>
                      <span className="feed-badge">{message.type}</span>
                      <p>{message.text}</p>
                    </div>
                  ))
                )}
              </div>
            </section>
          </section>
        </>
      )
    }

    if (activeTab === 'threats') {
      return (
        <section className="tab-layout">
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="panel-kicker">Detection Pipeline</p>
                <h3>Threat feed</h3>
              </div>
              <AlertTriangle size={18} />
            </div>
            <div className="stat-strip">
              <div className="strip-card"><span>Detections</span><strong>{detectionStats?.total_detections ?? 0}</strong></div>
              <div className="strip-card"><span>Avg confidence</span><strong>{formatPercent(detectionStats?.average_confidence)}</strong></div>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Time</th><th>Source</th><th>Level</th><th>Type</th><th>Status</th></tr></thead>
                <tbody>
                  {threats.length === 0 ? (
                    <tr><td colSpan="6" className="empty-table">No threats have been recorded yet.</td></tr>
                  ) : (
                    threats.map((threat) => (
                      <tr key={threat.id} className={selectedThreatId === threat.id ? 'is-selected' : ''} onClick={() => setSelectedThreatId(threat.id)}>
                        <td className="mono-cell">#{threat.id}</td>
                        <td>{formatTimestamp(threat.timestamp)}</td>
                        <td className="mono-cell">{threat.source_ip}</td>
                        <td><span className={`badge level-${threat.threat_level.toLowerCase()}`}>{threat.threat_level}</span></td>
                        <td>{labelize(threat.attack_type)}</td>
                        <td><span className="badge badge-soft">{labelize(threat.status)}</span></td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="panel-kicker">Threat Detail</p>
                <h3>Investigation context</h3>
              </div>
              <Target size={18} />
            </div>
            {!selectedThreat ? (
              <div className="empty-state">Select a threat to inspect its metadata and status.</div>
            ) : (
              <div className="detail-stack">
                <div className="detail-grid">
                  <div className="detail-card"><span className="detail-label">Source</span><strong className="mono-cell">{selectedThreat.source_ip}</strong></div>
                  <div className="detail-card"><span className="detail-label">Threat level</span><strong>{labelize(selectedThreat.threat_level)}</strong></div>
                  <div className="detail-card"><span className="detail-label">Attack type</span><strong>{labelize(selectedThreat.attack_type)}</strong></div>
                  <div className="detail-card"><span className="detail-label">Confidence</span><strong>{formatPercent(selectedThreat.confidence_score)}</strong></div>
                </div>
                <div className="detail-card">
                  <span className="detail-label">MITRE mapping</span>
                  <strong>{selectedThreat.mitre_tactic || selectedThreat.mitre_technique ? `${selectedThreat.mitre_tactic || 'No tactic'} / ${selectedThreat.mitre_technique || 'No technique'}` : 'No MITRE mapping attached'}</strong>
                </div>
                {selectedThreat.mitre_mappings?.length > 0 && (
                  <div className="detail-card">
                    <span className="detail-label">ATT&CK techniques</span>
                    <div className="mapping-list">
                      {selectedThreat.mitre_mappings.map((mapping, index) => (
                        <div key={`${mapping.technique_id}-${index}`} className="mapping-row">
                          <strong>{mapping.technique_id}</strong>
                          <span>{mapping.technique}</span>
                          <span>{mapping.tactic}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="action-row">
                  <button className="action-button" disabled={threatUpdateBusy} onClick={() => handleThreatStatusUpdate(selectedThreat.id, 'investigating')}>Mark investigating</button>
                  <button className="action-button success" disabled={threatUpdateBusy} onClick={() => handleThreatStatusUpdate(selectedThreat.id, 'resolved')}>Resolve</button>
                  <button className="action-button subtle" disabled={threatUpdateBusy} onClick={() => handleThreatStatusUpdate(selectedThreat.id, 'false_positive')}>False positive</button>
                </div>
              </div>
            )}
          </section>
        </section>
      )
    }

    if (activeTab === 'honeypot') {
      return (
        <section className="tab-layout">
          <section className="panel">
            <div className="panel-header">
              <div><p className="panel-kicker">Session Intake</p><h3>Recent honeypot sessions</h3></div>
              <TerminalSquare size={18} />
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Session</th><th>Type</th><th>Source</th><th>Started</th><th>User</th></tr></thead>
                <tbody>
                  {honeypotSessions.length === 0 ? (
                    <tr><td colSpan="5" className="empty-table">No honeypot sessions captured in the selected window.</td></tr>
                  ) : (
                    honeypotSessions.map((session) => (
                      <tr key={session.id}>
                        <td className="mono-cell">{session.session_id}</td>
                        <td>{labelize(session.honeypot_type)}</td>
                        <td className="mono-cell">{session.source_ip}:{session.source_port}</td>
                        <td>{formatTimestamp(session.start_time)}</td>
                        <td>{session.username || 'Anonymous'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <div><p className="panel-kicker">Operator Notes</p><h3>Session highlights</h3></div>
              <Shield size={18} />
            </div>
            <div className="session-stack">
              {honeypotSessions.length === 0 ? (
                <div className="empty-state">New sessions will appear here as the honeypot ingests data.</div>
              ) : (
                honeypotSessions.slice(0, 4).map((session) => (
                  <article key={session.id} className="session-card">
                    <div className="session-head"><strong>{labelize(session.honeypot_type)}</strong><span>{formatTimestamp(session.start_time)}</span></div>
                    <p className="mono-cell">{session.source_ip}</p>
                    <p>Commands: {session.commands?.length ? session.commands.slice(0, 3).join(', ') : 'No command activity captured'}</p>
                    <p>Payload: {session.payload ? 'Present' : 'None recorded'}</p>
                  </article>
                ))
              )}
            </div>
          </section>
        </section>
      )
    }

    if (activeTab === 'response') {
      return (
        <section className="tab-layout">
          <section className="panel">
            <div className="panel-header">
              <div><p className="panel-kicker">Containment</p><h3>Blocked IP registry</h3></div>
              <Ban size={18} />
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>IP Address</th><th>Reason</th><th>Count</th><th>Last blocked</th><th>Action</th></tr></thead>
                <tbody>
                  {blockedIps.length === 0 ? (
                    <tr><td colSpan="5" className="empty-table">No blocked IPs are currently recorded.</td></tr>
                  ) : (
                    blockedIps.map((entry) => (
                      <tr key={entry.id}>
                        <td className="mono-cell">{entry.ip_address}</td>
                        <td>{entry.reason || 'Threat response action'}</td>
                        <td>{entry.block_count}</td>
                        <td>{formatTimestamp(entry.last_blocked_at)}</td>
                        <td>{entry.is_active ? <button className="table-button" onClick={() => handleUnblock(entry.ip_address)}>Unblock</button> : <span className="badge badge-soft">Inactive</span>}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <div><p className="panel-kicker">Automation Log</p><h3>Recent response actions</h3></div>
              <Zap size={18} />
            </div>
            <div className="action-log">
              {responseActions.length === 0 ? (
                <div className="empty-state">No response actions have been executed yet.</div>
              ) : (
                responseActions.map((action) => (
                  <article key={action.id} className="feed-entry">
                    <div className="action-meta"><span className="feed-badge">{labelize(action.status)}</span><span>{formatTimestamp(action.timestamp)}</span></div>
                    <strong>{labelize(action.action_type)}</strong>
                    <p>Target: <span className="mono-cell">{action.target}</span></p>
                    <p>{action.automated ? 'Automated response path' : 'Manual operator action'}</p>
                  </article>
                ))
              )}
            </div>
          </section>
        </section>
      )
    }

    return (
      <section className="tab-layout">
        <section className="panel">
          <div className="panel-header">
            <div><p className="panel-kicker">Controls</p><h3>Response settings</h3></div>
            <Settings2 size={18} />
          </div>
          <form className="settings-form" onSubmit={handleSettingsSave}>
            <label className="field-row">
              <span>Automated response</span>
              <select value={String(settingsDraft.auto_response_enabled)} onChange={(event) => setSettingsDraft((current) => ({ ...current, auto_response_enabled: event.target.value === 'true' }))}>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </label>
            <label className="field-row">
              <span>Response cooldown (seconds)</span>
              <input type="number" min="0" value={settingsDraft.response_cooldown_seconds} onChange={(event) => setSettingsDraft((current) => ({ ...current, response_cooldown_seconds: Number(event.target.value) }))} />
            </label>
            <button className="action-button" type="submit" disabled={settingsBusy}>{settingsBusy ? 'Saving...' : 'Save settings'}</button>
          </form>
        </section>
        <section className="panel">
          <div className="panel-header">
            <div><p className="panel-kicker">System State</p><h3>Backend and thresholds</h3></div>
            <Server size={18} />
          </div>
          <div className="detail-stack">
            <div className="detail-grid">
              <div className="detail-card"><span className="detail-label">Health</span><strong>{labelize(health?.status)}</strong></div>
              <div className="detail-card"><span className="detail-label">Version</span><strong>{health?.version || '1.0.0'}</strong></div>
              <div className="detail-card"><span className="detail-label">Anomaly threshold</span><strong>{responseSettings?.anomaly_threshold ?? '--'}</strong></div>
              <div className="detail-card"><span className="detail-label">Confidence threshold</span><strong>{responseSettings?.confidence_threshold ?? '--'}</strong></div>
            </div>
            <div className="detail-card">
              <span className="detail-label">Components</span>
              <div className="component-list">
                {Object.entries(health?.components ?? {}).map(([name, status]) => (
                  <div key={name} className="component-row"><span>{labelize(name)}</span><strong>{labelize(status)}</strong></div>
                ))}
              </div>
            </div>
          </div>
        </section>
      </section>
    )
  }

  return (
    <div className={`app-shell ${darkMode ? 'dark' : ''}`}>
      <div className="dashboard-layout">
        <aside className="dashboard-sidebar">
          <div className="brand-panel">
            <div className="brand-mark">
              <Shield size={30} />
            </div>
            <div>
              <p className="eyebrow">AIRS Platform</p>
              <div className="brand-title-row">
                <h2>Adaptive Intrusion Response System</h2>
                <button
                  className="theme-icon-toggle"
                  onClick={() => setDarkMode((value) => !value)}
                  aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                  title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                  {darkMode ? <Sun size={16} /> : <Moon size={16} />}
                </button>
              </div>
              <p className="brand-copy">
                Move from monitoring to action with linked detection, honeypot, and response views.
              </p>
            </div>
          </div>

          <nav className="menu" aria-label="Dashboard sections">
            {menuItems.map((item) => {
              const Icon = item.icon

              return (
                <button
                  key={item.id}
                  className={`menu-item ${activeTab === item.id ? 'active' : ''}`}
                  onClick={() => startTransition(() => setActiveTab(item.id))}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </button>
              )
            })}
          </nav>

          <div className="sidebar-meta">
            <div className="meta-card">
              <span className="meta-label">Signal quality</span>
              <strong>{formatPercent(stats?.detection_accuracy_7d)}</strong>
            </div>
            <div className="meta-card">
              <span className="meta-label">Coverage</span>
              <strong>{formatAbsolutePercent(mitre?.tactic_coverage_percentage ?? mitre?.coverage_percentage)}</strong>
            </div>
          </div>

          <div className="sidebar-actions">
          </div>
        </aside>

        <main className="dashboard-main">
          {errors.length > 0 && (
            <div className="message message-error">
              {errors.map((error, index) => (
                <div key={`${error}-${index}`}>{error}</div>
              ))}
            </div>
          )}

          {flashMessage && <div className="message message-success">{flashMessage}</div>}

          {renderActiveTab()}
        </main>
      </div>
    </div>
  )
}

export default App
