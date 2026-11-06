import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { ErrorNote, SeverityBadge, StatusBadge, timeOf } from '../components/ui'

const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low']
const STATUSES = ['', 'open', 'blocked', 'resolved']
const SOURCES = ['', 'traffic', 'url']

/** @param {{ tick: number }} props  tick changes whenever a new event arrives */
export default function Alerts({ tick }) {
  const [filters, setFilters] = useState({ severity: '', status: '', source: '' })
  const [alerts, setAlerts] = useState([])
  const [error, setError] = useState('')

  const load = useCallback(() => {
    api.alerts({ ...filters, limit: 200 })
      .then((rows) => { setAlerts(rows); setError('') })
      .catch((e) => setError(`Cannot load alerts: ${e.message}`))
  }, [filters])

  useEffect(load, [load, tick])

  const setStatus = async (id, status) => {
    try {
      const updated = await api.updateAlert(id, status)
      setAlerts((rows) => rows.map((r) => (r.id === id ? updated : r)))
    } catch (e) {
      setError(e.message)
    }
  }

  const select = (key, options) => (
    <label>
      {key}
      <select value={filters[key]} onChange={(e) => setFilters({ ...filters, [key]: e.target.value })}>
        {options.map((o) => <option key={o} value={o}>{o || 'all'}</option>)}
      </select>
    </label>
  )

  return (
    <div className="page">
      <div className="card">
        <div className="filters">
          {select('severity', SEVERITIES)}
          {select('status', STATUSES)}
          {select('source', SOURCES)}
          <span className="muted">{alerts.length} alerts</span>
        </div>
        <ErrorNote error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th><th>Time</th><th>Severity</th><th>Threat</th><th>Source</th>
                <th>Source IP</th><th>Details</th><th>Conf.</th><th>Status</th><th>Action</th><th />
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td>{a.id}</td>
                  <td className="nowrap">{timeOf(a.created_at)}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.label}</td>
                  <td>{a.source}</td>
                  <td className="mono">{a.source_ip ?? '-'}</td>
                  <td className="ellipsis" title={a.summary}>{a.summary}</td>
                  <td>{(a.confidence * 100).toFixed(0)}%</td>
                  <td><StatusBadge status={a.status} /></td>
                  <td className="muted small">{a.action}</td>
                  <td>
                    {a.status !== 'resolved' && (
                      <button className="small-btn" onClick={() => setStatus(a.id, 'resolved')}>Resolve</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
