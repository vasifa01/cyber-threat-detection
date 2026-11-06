export const SEVERITY_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#38bdf8',
}

export function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge badge-safe">Safe</span>
  return (
    <span className="badge" style={{ background: SEVERITY_COLORS[severity] }}>
      {severity}
    </span>
  )
}

export function StatusBadge({ status }) {
  return <span className={`status status-${status}`}>{status}</span>
}

export function StatCard({ label, value, tone }) {
  return (
    <div className={`card stat ${tone ? `stat-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  )
}

export function ErrorNote({ error }) {
  if (!error) return null
  return <div className="error">{error}</div>
}

export function timeOf(iso) {
  return new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleTimeString()
}
