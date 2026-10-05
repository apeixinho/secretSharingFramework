import { useMemo, useState, type FormEvent } from 'react'
import { splitSecret } from '../lib/api'
import { useVault } from '../hooks/useVault'

export function SplitSecret() {
  const vault = useVault()
  const [k, setK] = useState(3)
  const [n, setN] = useState(5)
  const [secret, setSecret] = useState('')
  const [touched, setTouched] = useState({ k: false, n: false, secret: false })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const errors = useMemo(() => {
    const next = { k: '', n: '', secret: '' }
    if (!Number.isInteger(k) || k < 1) next.k = 'Threshold must be at least 1.'
    else if (k > 60) next.k = 'Threshold cannot exceed 60.'
    if (!Number.isInteger(n) || n < 1) next.n = 'Share count must be at least 1.'
    else if (n > 60) next.n = 'Share count cannot exceed 60.'
    else if (n < k) next.n = 'Share count (n) must be greater than or equal to threshold (k).'
    if (!secret.trim()) next.secret = 'Secret is required.'
    else if (secret.trim().length < 3) next.secret = 'Secret must be at least 3 characters.'
    else if (secret.length > 300) next.secret = 'Secret cannot exceed 300 characters.'
    return next
  }, [k, n, secret])

  const invalid = Boolean(errors.k || errors.n || errors.secret)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched({ k: true, n: true, secret: true })
    setError(null)
    setSuccess(null)
    if (invalid) return

    setBusy(true)
    try {
      const shares = await splitSecret({ k, n, secret: secret.trim() })
      vault.replace(shares, k, n)
      setSuccess(`Created ${shares.length} signed shares. Any ${k} can reconstruct the secret.`)
      document.getElementById('vault')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Split failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel" id="split" aria-labelledby="split-title">
      <div className="panel-intro">
        <p className="section-kicker">01 · Split</p>
        <h2 id="split-title">Fragment the secret</h2>
        <p>
          Choose a threshold <em>k</em> and total shares <em>n</em>. The API returns RSA-signed shares
          indexed from 1 to <em>n</em>.
        </p>
      </div>

      <form className="panel-body" noValidate onSubmit={onSubmit}>
        <div className="field-grid">
          <div className="field">
            <label htmlFor="threshold">Threshold (k)</label>
            <input
              id="threshold"
              type="number"
              inputMode="numeric"
              required
              value={k}
              onBlur={() => setTouched((t) => ({ ...t, k: true }))}
              onChange={(e) => setK(Number(e.target.value))}
            />
            {touched.k && errors.k ? (
              <p className="field-error" role="alert">
                {errors.k}
              </p>
            ) : null}
          </div>
          <div className="field">
            <label htmlFor="total-shares">Total shares (n)</label>
            <input
              id="total-shares"
              type="number"
              inputMode="numeric"
              required
              value={n}
              onBlur={() => setTouched((t) => ({ ...t, n: true }))}
              onChange={(e) => setN(Number(e.target.value))}
            />
            {touched.n && errors.n ? (
              <p className="field-error" role="alert">
                {errors.n}
              </p>
            ) : null}
          </div>
        </div>

        <div className="field">
          <label htmlFor="secret">Secret</label>
          <textarea
            id="secret"
            rows={4}
            placeholder="for-your-eyes-only"
            required
            value={secret}
            onBlur={() => setTouched((t) => ({ ...t, secret: true }))}
            onChange={(e) => setSecret(e.target.value)}
          />
          <div className="field-meta">
            <span>
              {secret.length} / 300
            </span>
            {touched.secret && errors.secret ? (
              <p className="field-error" role="alert">
                {errors.secret}
              </p>
            ) : null}
          </div>
        </div>

        {error ? (
          <p className="banner banner--error" role="alert">
            {error}
          </p>
        ) : null}
        {success ? (
          <p className="banner banner--ok" role="status">
            {success}
          </p>
        ) : null}

        <div className="actions">
          <button className="btn btn-primary" type="submit" disabled={busy || invalid}>
            {busy ? 'Splitting…' : 'Split secret'}
          </button>
        </div>
      </form>
    </section>
  )
}
