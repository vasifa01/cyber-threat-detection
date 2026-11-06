import { useState } from 'react'
import { useLiveFeed } from './hooks/useLiveFeed'
import Dashboard from './pages/Dashboard'
import UrlScanner from './pages/UrlScanner'
import Alerts from './pages/Alerts'
import Blocklist from './pages/Blocklist'

const TABS = ['Dashboard', 'URL Scanner', 'Alerts', 'Blocklist']

export default function App() {
  const [tab, setTab] = useState('Dashboard')
  const live = useLiveFeed()

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">🛡️</span>
          <div>
            <h1>AI Cyber Threat Detection</h1>
            <span className="muted small">Real-time detection, classification &amp; response</span>
          </div>
        </div>
        <nav>
          {TABS.map((t) => (
            <button key={t} className={t === tab ? 'tab active' : 'tab'} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </nav>
        <span className={live.connected ? 'live on' : 'live off'}>
          {live.connected ? '● LIVE' : '○ offline'}
        </span>
      </header>

      <main>
        {tab === 'Dashboard' && <Dashboard live={live} />}
        {tab === 'URL Scanner' && <UrlScanner />}
        {tab === 'Alerts' && <Alerts tick={live.tick} />}
        {tab === 'Blocklist' && <Blocklist tick={live.tick} />}
      </main>
    </div>
  )
}
