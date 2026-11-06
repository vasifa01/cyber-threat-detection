import { useEffect, useRef, useState } from 'react'
import { WS_URL } from '../api'

const MAX_FEED = 50

/**
 * Subscribes to the backend WebSocket and keeps the newest alerts in memory.
 * Reconnects automatically if the backend restarts.
 */
export function useLiveFeed() {
  const [alerts, setAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [tick, setTick] = useState(0) // bumps on every analysed event
  const retryRef = useRef(null)

  useEffect(() => {
    let ws
    let closed = false

    const connect = () => {
      ws = new WebSocket(WS_URL)
      ws.onopen = () => setConnected(true)
      ws.onclose = () => {
        setConnected(false)
        if (!closed) retryRef.current = setTimeout(connect, 2000)
      }
      ws.onerror = () => ws.close()
      ws.onmessage = (msg) => {
        let parsed
        try {
          parsed = JSON.parse(msg.data)
        } catch {
          return
        }
        if (parsed.type === 'alert') {
          setAlerts((prev) => [parsed.data, ...prev].slice(0, MAX_FEED))
        }
        setTick((t) => t + 1)
      }
    }

    connect()
    return () => {
      closed = true
      clearTimeout(retryRef.current)
      ws?.close()
    }
  }, [])

  return { alerts, connected, tick }
}
