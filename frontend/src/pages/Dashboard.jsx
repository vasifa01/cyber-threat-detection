import { useEffect, useState } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../api'
import { ErrorNote, SEVERITY_COLORS, SeverityBadge, StatCard, StatusBadge, timeOf } from '../components/ui'

const REFRESH_MS = 3000

/** @param {{ live: { alerts: object[], tick: number } }} props */
export default function Dashboard({ live }) {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    const load = () =>
      api.stats()
        .then((s) => { if (active) { setStats(s); setError('') } })
        .catch((e) => active && setError(`Cannot load stats: ${e.message}`))
    load()
    const id = setInterval(load, REFRESH_MS)
    return () => { active = false; clearInterval(id) }
  }, [])

  const byLabel = Object.entries(stats?.by_label ?? {}).map(([name, count]) => ({ name, count }))
  const bySeverity = Object.entries(stats?.by_severity ?? {}).map(([name, value]) => ({ name, value }))

  return (
    <div className="page">
      <ErrorNote error={error} />
      <section className="stats-grid">
        <StatCard label="Events analysed" value={stats?.total_events ?? '-'} />
        <StatCard label="Threats detected" value={stats?.threats ?? '-'} tone="danger" />
        <StatCard label="Detection rate" value={stats ? `${(stats.detection_rate * 100).toFixed(1)}%` : '-'} />
        <StatCard label="Open alerts" value={stats?.open_alerts ?? '-'} tone="warn" />
        <StatCard label="Blocked IPs" value={stats?.blocked_ips ?? '-'} tone="ok" />
        <StatCard label="Dropped requests" value={stats?.dropped ?? '-'} tone="ok" />
      </section>

      <section className="charts-grid">
        <div className="card chart-wide">
          <h3>Traffic vs threats (per minute)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={stats?.timeline ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" />
              <YAxis stroke="#64748b" allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Legend />
              <Area type="monotone" dataKey="events" stroke="#38bdf8" fill="#38bdf833" />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="#ef444433" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Threats by type</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={byLabel}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" />
              <YAxis stroke="#64748b" allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Bar dataKey="count" fill="#f97316" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Alerts by severity</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={bySeverity} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                {bySeverity.map((s) => <Cell key={s.name} fill={SEVERITY_COLORS[s.name]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="card">
        <h3>Live threat feed</h3>
        {live.alerts.length === 0 ? (
          <p className="muted">Waiting for threats... start the simulator or scan a URL.</p>
        ) : (
          <ul className="feed">
            {live.alerts.map((a) => (
              <li key={a.id} className="feed-item">
                <SeverityBadge severity={a.severity} />
                <span className="feed-label">{a.label}</span>
                <span className="mono muted">{a.source_ip ?? '-'}</span>
                <span className="feed-summary">{a.summary}</span>
                <StatusBadge status={a.status} />
                <span className="muted">{timeOf(a.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
