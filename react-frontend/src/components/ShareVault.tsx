import { useState } from 'react'
import { useVault } from '../hooks/useVault'

export function ShareVault() {
  const vault = useVault()
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  function toggleImport() {
    setImportOpen((open) => !open)
    setError(null)
    setNotice(null)
  }

  function importShares() {
    setError(null)
    setNotice(null)
    try {
      vault.importShares(importText)
      setImportOpen(false)
      setImportText('')
      setNotice('Shares imported into the vault.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not import shares.')
    }
  }

  async function copyShare(index: number) {
    const share = vault.snapshot.shares.find((item) => item.index === index)
    if (!share) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(share, null, 2))
      setCopiedIndex(index)
      window.setTimeout(() => {
        setCopiedIndex((current) => (current === index ? null : current))
      }, 1400)
    } catch {
      setError('Could not copy to clipboard.')
      setNotice(null)
    }
  }

  async function exportVault() {
    try {
      await navigator.clipboard.writeText(vault.exportJson())
      setNotice('Vault JSON copied to clipboard.')
      setError(null)
    } catch {
      setError('Could not copy vault JSON to clipboard.')
      setNotice(null)
    }
  }

  function clearVault() {
    vault.clearVault()
    setNotice('Vault cleared from this browser.')
    setError(null)
  }

  return (
    <section className="vault" id="vault" aria-labelledby="vault-title">
      <div className="vault-head">
        <div>
          <p className="section-kicker">02 · Vault</p>
          <h2 id="vault-title">Persistent share vault</h2>
          <p>
            Shares stay in this browser until you clear them. Select the fragments you will send to
            recover.
          </p>
        </div>
        <div className="vault-actions">
          <button type="button" className="btn btn-ghost-ink" onClick={toggleImport}>
            {importOpen ? 'Close import' : 'Import JSON'}
          </button>
          {vault.hasShares ? (
            <>
              <button type="button" className="btn btn-ghost-ink" onClick={() => void exportVault()}>
                Export
              </button>
              <button type="button" className="btn btn-ghost-ink" onClick={clearVault}>
                Clear
              </button>
            </>
          ) : null}
        </div>
      </div>

      {importOpen ? (
        <div className="import-box">
          <label htmlFor="import-json">Paste share JSON</label>
          <textarea
            id="import-json"
            rows={6}
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder='[{"index":1,"share":"...","signature":"..."}]'
          />
          <button type="button" className="btn btn-primary" onClick={importShares}>
            Import into vault
          </button>
        </div>
      ) : null}

      {notice ? (
        <p className="banner banner--ok" role="status">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="banner banner--error" role="alert">
          {error}
        </p>
      ) : null}

      {!vault.hasShares ? (
        <div className="empty">
          <p>No shares yet. Split a secret or import JSON to begin.</p>
        </div>
      ) : (
        <>
          <div className="meta-row">
            <span>
              Threshold <strong>{vault.snapshot.threshold ?? '—'}</strong>
            </span>
            <span>
              Total <strong>{vault.snapshot.totalShares ?? vault.snapshot.shares.length}</strong>
            </span>
            <span>
              Selected <strong>{vault.selectedCount}</strong>
            </span>
            <div className="selection-actions">
              <button type="button" className="text-btn" onClick={vault.selectThreshold}>
                Select k
              </button>
              <button type="button" className="text-btn" onClick={vault.selectAll}>
                Select all
              </button>
              <button type="button" className="text-btn" onClick={vault.clearSelection}>
                Clear selection
              </button>
            </div>
          </div>

          <ul className="share-list" role="list">
            {vault.snapshot.shares.map((share, i) => (
              <li className="share-card" key={share.index} style={{ ['--delay' as string]: `${i * 40}ms` }}>
                <label className="share-select">
                  <input
                    type="checkbox"
                    checked={vault.isSelected(share.index)}
                    onChange={() => vault.toggle(share.index)}
                  />
                  <span className="share-index">Share {share.index}</span>
                </label>
                <div className="share-body">
                  <div className="mono-block">
                    <span className="mono-label">Value</span>
                    <code>{share.share}</code>
                  </div>
                  <div className="mono-block">
                    <span className="mono-label">Signature</span>
                    <code>{share.signature}</code>
                  </div>
                </div>
                <button type="button" className="text-btn copy-btn" onClick={() => void copyShare(share.index)}>
                  {copiedIndex === share.index ? 'Copied' : 'Copy JSON'}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
