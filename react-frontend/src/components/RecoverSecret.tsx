import { useMemo, useState } from 'react'
import { recoverSecret } from '../lib/api'
import { useVault } from '../hooks/useVault'

export function RecoverSecret() {
  const vault = useVault()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recovered, setRecovered] = useState<string | null>(null)
  const [reveal, setReveal] = useState(false)

  const statusHint = useMemo(() => {
    if (!vault.hasShares) return 'Load shares into the vault before recovering.'
    if (vault.selectedCount === 0) return 'Select at least one share to recover.'
    if (!vault.ready) {
      const threshold = vault.snapshot.threshold
      return threshold == null
        ? 'Select more shares to recover.'
        : `Select at least ${threshold} shares (currently ${vault.selectedCount}).`
    }
    return `Ready to recover with ${vault.selectedCount} share(s).`
  }, [vault])

  const canRecover = vault.selectedCount > 0 && vault.ready && !busy

  async function recover() {
    setError(null)
    setRecovered(null)
    setReveal(false)
    if (!canRecover) {
      setError(statusHint)
      return
    }
    setBusy(true)
    try {
      const secret = await recoverSecret(vault.selected)
      setRecovered(secret)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery failed.')
    } finally {
      setBusy(false)
    }
  }

  async function copySecret(): Promise<void> {
    if (!recovered) return
    try {
      await navigator.clipboard.writeText(recovered)
    } catch {
      setError('Could not copy secret to clipboard.')
    }
  }

  return (
    <section className="recover" id="recover" aria-labelledby="recover-title">
      <div className="recover-intro">
        <p className="section-kicker">03 · Recover</p>
        <h2 id="recover-title">Reassemble the secret</h2>
        <p>
          The API verifies each share signature, then interpolates the secret from the selected
          fragments. Signatures only validate against the process that issued them.
        </p>
      </div>

      <div className="recover-body">
        <p className={`status${canRecover ? ' status--ready' : ''}`}>{statusHint}</p>
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={!canRecover} onClick={() => void recover()}>
            {busy ? 'Recovering…' : 'Recover secret'}
          </button>
        </div>

        {error ? (
          <p className="banner banner--error" role="alert">
            {error}
          </p>
        ) : null}

        {recovered ? (
          <div className="result" role="status">
            <div className="result-head">
              <h3>Recovered secret</h3>
              <div className="result-actions">
                <button type="button" className="text-btn" onClick={() => setReveal((v) => !v)}>
                  {reveal ? 'Hide' : 'Reveal'}
                </button>
                <button type="button" className="text-btn" onClick={() => void copySecret()}>
                  Copy
                </button>
              </div>
            </div>
            <pre className={reveal ? undefined : 'blurred'}>{recovered}</pre>
          </div>
        ) : null}
      </div>
    </section>
  )
}
