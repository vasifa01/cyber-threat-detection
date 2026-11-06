export const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'
export const WS_URL = API_URL.replace(/^http/, 'ws') + '/ws/alerts'

async function request(path, options = {}) {
  const res = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (res.status === 204) return null
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    const detail = Array.isArray(body.detail)
      ? body.detail.map((d) => d.msg).join('; ')
      : body.detail
    throw new Error(detail || `Request failed (${res.status})`)
  }
  return body
}

export const api = {
  stats: () => request('/api/stats'),
  alerts: (params = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v)
    ).toString()
    return request(`/api/alerts${qs ? `?${qs}` : ''}`)
  },
  updateAlert: (id, status) =>
    request(`/api/alerts/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  analyzeUrl: (url) =>
    request('/api/analyze/url', { method: 'POST', body: JSON.stringify({ url }) }),
  blocklist: () => request('/api/blocklist'),
  block: (ip, reason) =>
    request('/api/blocklist', { method: 'POST', body: JSON.stringify({ ip, reason }) }),
  unblock: (ip) => request(`/api/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
}
