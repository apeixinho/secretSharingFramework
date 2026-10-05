import { useCallback, useEffect, useState } from 'react'
import { checkHealth } from '../lib/api'
import type { ApiHealthStatus } from '../lib/models'

export function SiteHeader() {
  const [health, setHealth] = useState<ApiHealthStatus>('unknown')

  const refresh = useCallback(() => {
    void checkHealth().then(setHealth)
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const label =
    health === 'online' ? 'API online' : health === 'offline' ? 'API offline' : 'Checking API'

  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="Secret Sharing home">
        <span className="brand-mark" aria-hidden="true" />
        <span className="brand-text">Secret Sharing</span>
      </a>

      <nav className="nav" aria-label="Primary">
        <a href="#split">Split</a>
        <a href="#vault">Vault</a>
        <a href="#recover">Recover</a>
      </nav>

      <button
        type="button"
        className={`health${health === 'online' ? ' health--online' : ''}${
          health === 'offline' ? ' health--offline' : ''
        }`}
        aria-label={`${label}. Click to refresh.`}
        onClick={refresh}
      >
        <span className="health-dot" aria-hidden="true" />
        <span>{label}</span>
      </button>
    </header>
  )
}
