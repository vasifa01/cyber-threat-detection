import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { ErrorNote, timeOf } from '../components/ui'

/** @param {{ tick: number }} props */
export default function Blocklist({ tick }) {
  const [rows, setRows] = useState([])
  const [ip, setIp] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(() => {
    api.blocklist()
      .then((r) => { setRows(r); setError('') })
      .catch((e) => setError(`Cannot load blocklist: ${e.message}`))
  }, [])

  useEffect(load, [load, tick])

  const block = async (e) => {
    e.preventDefault()
    try {
      await api.block(ip.trim(), 'Manually blocked by analyst')
      setIp('')
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  const unblock = async (target) => {
    try {
      await api.unblock(target)
      setRows((r) => r.filter((x) => x.ip !== target))
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="page narrow">
      <div className="card">
        <h3>Firewall blocklist</h3>
        <p className="muted">
          High and Critical threats automatically block their source IP. Further requests from a
          blocked IP are dropped and counted, but no new alert is raised.
        </p>
        <form className="row" onSubmit={block}>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address to block" />
          <button disabled={!ip.trim()}>Block</button>
        </form>
        <ErrorNote error={error} />
        <table>
          <thead><tr><th>IP</th><th>Reason</th><th>Blocked at</th><th /></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.ip}</td>
                <td>{r.reason}</td>
                <td>{timeOf(r.created_at)}</td>
                <td><button className="small-btn" onClick={() => unblock(r.ip)}>Unblock</button></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={4} className="muted">No blocked IPs yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
