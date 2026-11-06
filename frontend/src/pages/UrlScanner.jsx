import { useState } from 'react'
import { api } from '../api'
import { ErrorNote, SeverityBadge } from '../components/ui'

const EXAMPLES = [
  'en.wikipedia.org/wiki/Computer_security',
  'paypal.com.verify-account-login.tk/webscr/signin.php',
  'free-bonus-wallet.xyz/download/setup.exe',
]

const INDICATOR_LABELS = {
  has_ip_host: 'Raw IP address instead of a domain',
  suspicious_word_count: 'Suspicious keywords (login, verify, bank...)',
  has_suspicious_tld: 'High-risk top-level domain',
  has_executable_ext: 'Links to an executable / archive',
  num_at: "Contains '@' (can hide the real host)",
  num_hyphens: 'Hyphens in URL',
  num_subdomains: 'Extra subdomains',
}

export default function UrlScanner() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const scan = async (target) => {
    const value = (target ?? url).trim()
    if (!value) return
    setUrl(value)
    setLoading(true)
    setError('')
    try {
      setResult(await api.analyzeUrl(value))
    } catch (e) {
      setResult(null)
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const redFlags = Object.entries(result?.indicators ?? {})
    .filter(([key]) => key in INDICATOR_LABELS)

  return (
    <div className="page narrow">
      <div className="card">
        <h3>Phishing &amp; malware URL scanner</h3>
        <form className="row" onSubmit={(e) => { e.preventDefault(); scan() }}>
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste a URL, e.g. secure-login.example.tk/verify"
            maxLength={2048}
          />
          <button disabled={loading}>{loading ? 'Scanning...' : 'Scan'}</button>
        </form>
        <div className="examples">
          Try:
          {EXAMPLES.map((ex) => (
            <button key={ex} className="link" onClick={() => scan(ex)}>{ex}</button>
          ))}
        </div>
        <ErrorNote error={error} />
      </div>

      {result && (
        <div className={`card result ${result.is_threat ? 'result-bad' : 'result-good'}`}>
          <div className="result-head">
            <h2>{result.label}</h2>
            <SeverityBadge severity={result.severity} />
          </div>
          <p>{result.description}</p>
          <p className="muted">Model confidence: {(result.confidence * 100).toFixed(1)}%</p>
          {result.action && <p><strong>Response:</strong> {result.action}</p>}
          {redFlags.length > 0 && (
            <>
              <h4>Indicators found</h4>
              <ul>
                {redFlags.map(([key, value]) => (
                  <li key={key}>{INDICATOR_LABELS[key]} ({value})</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  )
}
