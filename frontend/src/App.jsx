import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_ROOT = '/api/v1'

function App() {
  const [stats, setStats] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [mitre, setMitre] = useState(null)
  const [health, setHealth] = useState(null)
  const [errors, setErrors] = useState([])
  const [loading, setLoading] = useState(true)
  const [socketMessages, setSocketMessages] = useState([])
  const [darkMode, setDarkMode] = useState(false)

  useEffect(() => {
    async function loadAll() {
      setLoading(true)
      const promises = [
        fetch(`${API_ROOT}/dashboard/stats`),
        fetch(`${API_ROOT}/dashboard/timeline?hours=24&interval=hour`),
        fetch(`${API_ROOT}/dashboard/mitre-coverage`),
        fetch(`${API_ROOT}/dashboard/system-health`)
      ]

      try {
        const [statsRes, timelineRes, mitreRes, healthRes] = await Promise.all(promises)

        if (!statsRes.ok || !timelineRes.ok || !mitreRes.ok || !healthRes.ok) {
          throw new Error('One or more dashboard endpoints failed (backend may not be running).')
        }

        setStats(await statsRes.json())
        setTimeline(await timelineRes.json())
        setMitre(await mitreRes.json())
        setHealth(await healthRes.json())
      } catch (err) {
        setErrors((prev) => [...prev, err.message || 'Unexpected dashboard error'])
      } finally {
        setLoading(false)
      }
    }

    loadAll()
  }, [])

  useEffect(() => {
    let ws
    let reconnectTimer

    const connectWs = () => {
      const backendHost = window.location.hostname || 'localhost'
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${wsProtocol}//${backendHost}:8000/api/v1/dashboard/ws`

      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setSocketMessages((m) => [...m, { type: 'system', text: 'WebSocket connected' }])
        ws.send('subscribe')
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setSocketMessages((m) => [...m, { type: data.type || 'message', text: JSON.stringify(data) }])
        } catch {
          setSocketMessages((m) => [...m, { type: 'message', text: event.data }])
        }
      }

      ws.onerror = () => {
        setSocketMessages((m) => [...m, { type: 'error', text: 'WebSocket connection error' }])
      }

      ws.onclose = () => {
        setSocketMessages((m) => [...m, { type: 'system', text: 'WebSocket closed, reconnecting in 3s...' }])
        reconnectTimer = setTimeout(connectWs, 3000)
      }
    }

    connectWs()
    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [])

  const timelineMax = useMemo(() => {
    if (!timeline.length) return 1
    return Math.max(...timeline.map((x) => x.value), 1)
  }, [timeline])

  return (
    <div className={`app-shell ${darkMode ? 'dark' : ''}`}>
      <div className="dashboard-layout">
        <aside className="dashboard-sidebar">
          <div className="brand">
            <p className="tag">AIRS</p>
            <h2>Security Command Center</h2>
            <p className="brand-sub">Real-time intrusion monitoring</p>
          </div>
          <nav className="menu">
            <button className="menu-item active">Overview</button>
            <button className="menu-item">Threats</button>
            <button className="menu-item">Honeypot</button>
            <button className="menu-item">Response</button>
            <button className="menu-item">Settings</button>
          </nav>
          <div className="sidebar-footer">
            <button className="toggle" onClick={() => setDarkMode((v) => !v)}>
              {darkMode ? '☀ Light' : '🌙 Dark'}
            </button>
          </div>
        </aside>

        <main className="dashboard-main">
          <header className="headline">
            <div>
              <p className="tag">AIRS Dashboard</p>
              <h1>Threat Monitoring</h1>
              <p className="subtitle">Live FastAPI metrics and alerts</p>
            </div>
            <div className="health-pill">
              <span>Backend</span>
              <strong>{health?.status ?? 'unknown'}</strong>
            </div>
          </header>

          {loading && <div className="message">Loading dashboard data...</div>}
          {errors.length > 0 && (
            <div className="message message-error">
              {errors.map((err, i) => <div key={`${err}-${i}`}>{err}</div>)}
            </div>
          )}

          {!loading && stats && (
            <>
              <section className="card-grid">
                <div className="card"><span>Total sessions (24h)</span><strong>{stats.total_sessions_24h}</strong></div>
                <div className="card"><span>Active threats</span><strong>{stats.active_threats}</strong></div>
                <div className="card"><span>Blocked IPs</span><strong>{stats.blocked_ips}</strong></div>
                <div className="card"><span>Detection accuracy (7d)</span><strong>{(stats.detection_accuracy_7d * 100).toFixed(1)}%</strong></div>
              </section>

              <section className="section-row">
                <section className="section card-block">
                  <h2 className="section-heading">Threat timeline (24h)</h2>
                  <div className="timeline">
                    {timeline.length === 0 ? <div>No timeline data</div> : timeline.map((item, idx) => (
                      <div key={`${item.timestamp}-${idx}`} className="bar-wrap">
                        <div className="bar-label">{new Date(item.timestamp).getHours()}:00</div>
                        <div className="bar" style={{ height: `${(item.value / timelineMax) * 120 + 10}px` }} title={`${item.value} events`} />
                      </div>
                    ))}
                  </div>
                </section>

                <section className="section card-block">
                  <h2 className="section-heading">MITRE coverage</h2>
                  <div className="data-pair">
                    <div><strong>Tactics observed:</strong> {mitre?.tactics_observed ?? 0}</div>
                    <div><strong>Techniques:</strong> {mitre?.techniques_observed ?? 0}</div>
                    <div><strong>Coverage:</strong> {mitre?.coverage_percentage ?? 0}%</div>
                  </div>
                </section>
              </section>

              <section className="section card-block">
                <h2 className="section-heading">Recent alerts</h2>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>ID</th><th>Time</th><th>IP</th><th>Level</th><th>Type</th><th>Status</th></tr></thead>
                    <tbody>{stats.recent_alerts?.slice(0, 8).map((a) => (
                      <tr key={a.id}><td>{a.id}</td><td>{new Date(a.timestamp).toLocaleString()}</td><td>{a.source_ip}</td><td>{a.threat_level}</td><td>{a.attack_type}</td><td>{a.status}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </section>

              <section className="section card-block">
                <h2 className="section-heading">Live events (WebSocket)</h2>
                <div className="log-box">
                  {socketMessages.slice(-6).map((message, idx) => (
                    <div key={`${message.type}-${idx}`} className={message.type === 'error' ? 'log-error' : ''}>
                      <strong>[{message.type}]</strong> {message.text}
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
