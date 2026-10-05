import './style.css'
import { checkHealth, recoverSecret, splitSecret } from './lib/api'
import type { ApiHealthStatus, ShareVaultSnapshot } from './lib/models'
import {
  clearSelection,
  clearVault,
  exportJson,
  importShares,
  meetsThreshold,
  persistSnapshot,
  readStorage,
  replaceShares,
  selectAll,
  selectThreshold,
  selectedShares,
  toggleShare,
} from './lib/vault'

interface AppState {
  health: ApiHealthStatus
  vault: ShareVaultSnapshot
  k: number
  n: number
  secret: string
  splitBusy: boolean
  splitError: string | null
  splitSuccess: string | null
  importOpen: boolean
  importText: string
  vaultNotice: string | null
  vaultError: string | null
  copiedIndex: number | null
  recoverBusy: boolean
  recoverError: string | null
  recovered: string | null
  reveal: boolean
}

const state: AppState = {
  health: 'unknown',
  vault: readStorage(),
  k: 3,
  n: 5,
  secret: '',
  splitBusy: false,
  splitError: null,
  splitSuccess: null,
  importOpen: false,
  importText: '',
  vaultNotice: null,
  vaultError: null,
  copiedIndex: null,
  recoverBusy: false,
  recoverError: null,
  recovered: null,
  reveal: false,
}

const app = document.querySelector<HTMLDivElement>('#app')
if (!app) {
  throw new Error('Missing #app root')
}

function setState(patch: Partial<AppState>, options?: { persist?: boolean; remount?: boolean }) {
  Object.assign(state, patch)
  const shouldPersist = options?.persist ?? Object.prototype.hasOwnProperty.call(patch, 'vault')
  if (shouldPersist) {
    persistSnapshot(state.vault)
  }
  render(options?.remount ?? true)
}

function healthLabel(): string {
  if (state.health === 'online') return 'API online'
  if (state.health === 'offline') return 'API offline'
  return 'Checking API'
}

function validateSplit(): { k: string; n: string; secret: string } {
  const errors = { k: '', n: '', secret: '' }
  if (!Number.isInteger(state.k) || state.k < 1) errors.k = 'Threshold must be at least 1.'
  else if (state.k > 60) errors.k = 'Threshold cannot exceed 60.'
  if (!Number.isInteger(state.n) || state.n < 1) errors.n = 'Share count must be at least 1.'
  else if (state.n > 60) errors.n = 'Share count cannot exceed 60.'
  else if (state.n < state.k) errors.n = 'Share count (n) must be greater than or equal to threshold (k).'
  if (!state.secret.trim()) errors.secret = 'Secret is required.'
  else if (state.secret.trim().length < 3) errors.secret = 'Secret must be at least 3 characters.'
  else if (state.secret.length > 300) errors.secret = 'Secret cannot exceed 300 characters.'
  return errors
}

function statusHint(): string {
  if (state.vault.shares.length === 0) return 'Load shares into the vault before recovering.'
  if (state.vault.selectedIndexes.length === 0) return 'Select at least one share to recover.'
  if (!meetsThreshold(state.vault)) {
    const threshold = state.vault.threshold
    return threshold == null
      ? 'Select more shares to recover.'
      : `Select at least ${threshold} shares (currently ${state.vault.selectedIndexes.length}).`
  }
  return `Ready to recover with ${state.vault.selectedIndexes.length} share(s).`
}

function canRecover(): boolean {
  return (
    state.vault.selectedIndexes.length > 0 &&
    meetsThreshold(state.vault) &&
    !state.recoverBusy
  )
}

function btnPrimary(extra = ''): string {
  return `inline-flex items-center justify-center min-h-11 px-4.5 rounded-full bg-teal text-[#f4fbf8] border border-teal/70 font-semibold hover:bg-teal-deep disabled:opacity-55 disabled:cursor-not-allowed ${extra}`
}

function btnGhostInk(extra = ''): string {
  return `inline-flex items-center justify-center min-h-11 px-4.5 rounded-full border border-ink/20 text-ink bg-transparent hover:bg-white/45 ${extra}`
}

function btnGhost(extra = ''): string {
  return `inline-flex items-center justify-center min-h-11 px-4.5 rounded-full border border-mist/30 text-mist bg-transparent hover:bg-mist/10 ${extra}`
}

function textBtn(dark = false): string {
  return dark
    ? 'border-0 bg-transparent text-brass underline underline-offset-2 font-semibold text-sm cursor-pointer hover:text-mist'
    : 'border-0 bg-transparent text-teal-deep underline underline-offset-2 font-semibold text-sm cursor-pointer hover:text-ink'
}

function renderShell(): string {
  const selected = selectedShares(state.vault)
  const splitErrors = validateSplit()
  const splitInvalid = Boolean(splitErrors.k || splitErrors.n || splitErrors.secret)
  const ready = canRecover()

  return `
  <header class="sticky top-0 z-20 flex items-center justify-between gap-4 px-4 md:px-8 py-3.5 backdrop-blur-md bg-ink/80 border-b border-mist/10">
    <a href="#top" class="inline-flex items-center gap-2.5 text-mist no-underline min-w-0" aria-label="Secret Sharing home">
      <span class="brand-mark w-3.5 h-3.5 shrink-0 bg-linear-to-br from-teal to-brass" aria-hidden="true"></span>
      <span class="font-display text-[1.05rem] tracking-tight truncate">Secret Sharing</span>
    </a>
    <nav class="hidden md:inline-flex gap-5" aria-label="Primary">
      <a class="text-mist/80 hover:text-mist text-[0.92rem] no-underline" href="#split">Split</a>
      <a class="text-mist/80 hover:text-mist text-[0.92rem] no-underline" href="#vault">Vault</a>
      <a class="text-mist/80 hover:text-mist text-[0.92rem] no-underline" href="#recover">Recover</a>
    </nav>
    <button type="button" data-action="refresh-health" aria-label="${healthLabel()}. Click to refresh."
      class="inline-flex items-center gap-2 rounded-full border border-mist/20 bg-ink-soft/80 text-mist/85 px-3 py-1.5 text-xs cursor-pointer">
      <span class="w-2 h-2 rounded-full ${
        state.health === 'online'
          ? 'bg-teal-bright shadow-[0_0_0_4px_color-mix(in_srgb,var(--color-teal-bright)_18%,transparent)]'
          : state.health === 'offline'
            ? 'bg-[#d97862]'
            : 'bg-mist/45'
      }" aria-hidden="true"></span>
      <span>${healthLabel()}</span>
    </button>
  </header>

  <main>
    <section class="relative min-h-[min(92vh,860px)] grid items-end overflow-hidden isolate px-[clamp(1.1rem,4vw,3rem)] pt-[clamp(5.5rem,12vh,8rem)] pb-[clamp(2.5rem,7vh,4.5rem)] bg-[radial-gradient(ellipse_70%_55%_at_78%_28%,color-mix(in_srgb,#2f7a6b_28%,transparent),transparent_70%),radial-gradient(ellipse_55%_45%_at_18%_70%,color-mix(in_srgb,#c9b07a_14%,transparent),transparent_70%),linear-gradient(165deg,#101816_0%,#0c1110_48%,#0a100f_100%)]" id="top" aria-labelledby="hero-brand">
      <div class="absolute inset-0 -z-10 pointer-events-none" aria-hidden="true">
        <svg class="w-full h-full opacity-90" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
          <defs>
            <linearGradient id="shardFill" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3d8b7a" stop-opacity="0.55" />
              <stop offset="100%" stop-color="#c9b07a" stop-opacity="0.25" />
            </linearGradient>
            <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#9eb7ad" stop-opacity="0" />
              <stop offset="50%" stop-color="#9eb7ad" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#9eb7ad" stop-opacity="0" />
            </linearGradient>
          </defs>
          <g stroke="url(#lineGrad)" stroke-width="1" fill="none">
            <path class="animate-link" d="M180 170 L420 250 L610 160 L860 240 L1040 150" />
            <path class="animate-link" d="M220 420 L470 360 L700 470 L930 390" />
            <path class="animate-link" d="M300 620 L540 540 L780 650 L980 560" />
          </g>
          <g fill="url(#shardFill)" stroke="#9eb7ad" stroke-opacity="0.28" stroke-width="1">
            <polygon class="animate-shard" points="180,150 230,170 210,230 155,210" />
            <polygon class="animate-shard" style="animation-delay:-1.2s" points="420,230 480,210 510,270 445,295" />
            <polygon class="animate-shard" style="animation-delay:-2.4s" points="610,140 670,165 645,225 585,205" />
            <polygon class="animate-shard" style="animation-delay:-3.1s" points="860,220 920,200 945,260 880,285" />
            <polygon class="animate-shard" style="animation-delay:-0.7s" points="1040,130 1090,155 1065,210 1010,185" />
            <polygon class="animate-shard" style="animation-delay:-4.2s" points="470,340 530,320 555,385 490,405" />
            <polygon class="animate-shard" style="animation-delay:-2.8s" points="700,450 760,430 785,500 715,520" />
            <polygon class="animate-shard" style="animation-delay:-5.1s" points="540,520 600,500 625,570 555,590" />
            <polygon class="animate-shard" style="animation-delay:-1.8s" points="930,370 990,350 1015,415 950,435" />
          </g>
        </svg>
      </div>
      <div class="max-w-xl animate-rise">
        <p class="m-0 mb-3.5 text-brass/90 text-[0.82rem] tracking-[0.14em] uppercase">Shamir threshold cryptography</p>
        <h1 id="hero-brand" class="m-0 font-display text-[clamp(3.1rem,9vw,5.6rem)] font-medium leading-[0.95] tracking-[-0.035em] text-mist">Secret Sharing</h1>
        <p class="mt-4.5 max-w-md text-mist/80 text-[clamp(1.05rem,2.4vw,1.25rem)] leading-relaxed">
          Split a secret into signed shares. Reassemble it only when enough trusted fragments return.
        </p>
        <div class="flex flex-wrap gap-3 mt-7">
          <a class="${btnPrimary()}" href="#split">Split a secret</a>
          <a class="${btnGhost()}" href="#recover">Recover from shares</a>
        </div>
      </div>
    </section>

    <section class="bg-[radial-gradient(ellipse_60%_40%_at_100%_0%,color-mix(in_srgb,#2f7a6b_10%,transparent),transparent_60%),linear-gradient(180deg,#e7eeea_0%,#dce6e1_100%)] text-ink" aria-label="Split and vault">
      <div class="w-[min(1120px,calc(100%-2rem))] mx-auto grid gap-[clamp(2.5rem,6vw,4rem)] py-[clamp(2.75rem,7vw,4.5rem)]">
        <section class="grid gap-6 lg:grid-cols-[minmax(14rem,0.9fr)_minmax(0,1.3fr)] lg:gap-10 lg:items-start" id="split" aria-labelledby="split-title">
          <div>
            <p class="m-0 text-[0.78rem] tracking-[0.14em] uppercase text-teal-deep/80">01 · Split</p>
            <h2 id="split-title" class="mt-1.5 mb-3 font-display text-[clamp(1.8rem,4vw,2.4rem)] font-medium tracking-tight">Fragment the secret</h2>
            <p class="m-0 max-w-md text-ink/70 leading-relaxed">
              Choose a threshold <em>k</em> and total shares <em>n</em>. The API returns RSA-signed shares indexed from 1 to <em>n</em>.
            </p>
          </div>
          <form id="split-form" class="grid gap-4 p-5 rounded-2xl bg-white/55 border border-ink/10" novalidate>
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="grid gap-2">
                <label for="threshold" class="text-sm font-semibold text-ink/80">Threshold (k)</label>
                <input id="threshold" name="k" type="number" inputmode="numeric" required value="${state.k}"
                  class="w-full rounded-xl border border-ink/15 bg-white/70 text-ink px-3.5 py-3 focus:outline-none focus:border-teal focus:ring-3 focus:ring-teal/20" />
              </div>
              <div class="grid gap-2">
                <label for="total-shares" class="text-sm font-semibold text-ink/80">Total shares (n)</label>
                <input id="total-shares" name="n" type="number" inputmode="numeric" required value="${state.n}"
                  class="w-full rounded-xl border border-ink/15 bg-white/70 text-ink px-3.5 py-3 focus:outline-none focus:border-teal focus:ring-3 focus:ring-teal/20" />
              </div>
            </div>
            <div class="grid gap-2">
              <label for="secret" class="text-sm font-semibold text-ink/80">Secret</label>
              <textarea id="secret" name="secret" rows="4" required placeholder="for-your-eyes-only"
                class="w-full min-h-28 rounded-xl border border-ink/15 bg-white/70 text-ink px-3.5 py-3 resize-y focus:outline-none focus:border-teal focus:ring-3 focus:ring-teal/20">${escapeHtml(state.secret)}</textarea>
              <div class="flex justify-between text-xs text-ink/55"><span data-secret-count>${state.secret.length} / 300</span></div>
            </div>
            ${state.splitError ? `<p class="m-0 p-3 rounded-lg bg-[#9b3d2e]/12 text-[#7a2f24] text-sm" role="alert">${escapeHtml(state.splitError)}</p>` : ''}
            ${state.splitSuccess ? `<p class="m-0 p-3 rounded-lg bg-teal/15 text-teal-deep text-sm" role="status">${escapeHtml(state.splitSuccess)}</p>` : ''}
            <div class="flex justify-end">
              <button class="${btnPrimary()}" type="submit" ${state.splitBusy || splitInvalid ? 'disabled' : ''}>
                ${state.splitBusy ? 'Splitting…' : 'Split secret'}
              </button>
            </div>
          </form>
        </section>

        <section id="vault" aria-labelledby="vault-title">
          <div class="flex flex-wrap gap-4 justify-between items-end mb-5">
            <div>
              <p class="m-0 text-[0.78rem] tracking-[0.14em] uppercase text-teal-deep/80">02 · Vault</p>
              <h2 id="vault-title" class="mt-1.5 mb-3 font-display text-[clamp(1.8rem,4vw,2.4rem)] font-medium tracking-tight">Persistent share vault</h2>
              <p class="m-0 max-w-md text-ink/70 leading-relaxed">Shares stay in this browser until you clear them. Select the fragments you will send to recover.</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <button type="button" data-action="toggle-import" class="${btnGhostInk()}">${state.importOpen ? 'Close import' : 'Import JSON'}</button>
              ${
                state.vault.shares.length
                  ? `<button type="button" data-action="export-vault" class="${btnGhostInk()}">Export</button>
                     <button type="button" data-action="clear-vault" class="${btnGhostInk()}">Clear</button>`
                  : ''
              }
            </div>
          </div>

          ${
            state.importOpen
              ? `<div class="grid gap-3 mb-4 p-4 rounded-2xl bg-white/55 border border-ink/10">
                  <label for="import-json" class="text-sm font-semibold">Paste share JSON</label>
                  <textarea id="import-json" rows="6" placeholder='[{"index":1,"share":"...","signature":"..."}]'
                    class="w-full rounded-xl border border-ink/15 bg-white/70 text-ink px-3.5 py-3 font-mono text-sm resize-y">${escapeHtml(state.importText)}</textarea>
                  <button type="button" data-action="import-shares" class="${btnPrimary()} w-fit">Import into vault</button>
                </div>`
              : ''
          }

          ${state.vaultNotice ? `<p class="mb-4 p-3 rounded-lg bg-teal/15 text-teal-deep text-sm" role="status">${escapeHtml(state.vaultNotice)}</p>` : ''}
          ${state.vaultError ? `<p class="mb-4 p-3 rounded-lg bg-[#9b3d2e]/12 text-[#7a2f24] text-sm" role="alert">${escapeHtml(state.vaultError)}</p>` : ''}

          ${
            state.vault.shares.length === 0
              ? `<div class="p-8 rounded-2xl border border-dashed border-ink/20 text-center text-ink/60"><p class="m-0">No shares yet. Split a secret or import JSON to begin.</p></div>`
              : `<div class="flex flex-wrap gap-x-5 gap-y-3 items-center mb-4 text-sm text-ink/70">
                  <span>Threshold <strong class="text-ink ml-1">${state.vault.threshold ?? '—'}</strong></span>
                  <span>Total <strong class="text-ink ml-1">${state.vault.totalShares ?? state.vault.shares.length}</strong></span>
                  <span>Selected <strong class="text-ink ml-1">${selected.length}</strong></span>
                  <div class="inline-flex flex-wrap gap-2.5 ml-auto">
                    <button type="button" data-action="select-k" class="${textBtn()}">Select k</button>
                    <button type="button" data-action="select-all" class="${textBtn()}">Select all</button>
                    <button type="button" data-action="clear-selection" class="${textBtn()}">Clear selection</button>
                  </div>
                </div>
                <ul class="list-none m-0 p-0 grid gap-3.5" role="list">
                  ${state.vault.shares
                    .map(
                      (share, i) => `
                    <li class="animate-card grid gap-3.5 p-4 rounded-2xl bg-white/60 border border-ink/10 lg:grid-cols-[auto_1fr_auto] lg:items-start" style="animation-delay:${i * 40}ms">
                      <label class="inline-flex items-center gap-2.5 cursor-pointer font-semibold">
                        <input type="checkbox" data-action="toggle-share" data-index="${share.index}" ${
                          state.vault.selectedIndexes.includes(share.index) ? 'checked' : ''
                        } class="w-4 h-4 accent-teal" />
                        <span>Share ${share.index}</span>
                      </label>
                      <div class="grid gap-2.5 min-w-0">
                        <div class="grid gap-1">
                          <span class="text-[0.72rem] tracking-wider uppercase text-ink/55">Value</span>
                          <code class="block overflow-auto max-h-18 break-all font-mono text-xs leading-relaxed p-2.5 rounded-lg bg-ink/5">${escapeHtml(share.share)}</code>
                        </div>
                        <div class="grid gap-1">
                          <span class="text-[0.72rem] tracking-wider uppercase text-ink/55">Signature</span>
                          <code class="block overflow-auto max-h-18 break-all font-mono text-xs leading-relaxed p-2.5 rounded-lg bg-ink/5">${escapeHtml(share.signature)}</code>
                        </div>
                      </div>
                      <button type="button" data-action="copy-share" data-index="${share.index}" class="${textBtn()} justify-self-start">${
                        state.copiedIndex === share.index ? 'Copied' : 'Copy JSON'
                      }</button>
                    </li>`,
                    )
                    .join('')}
                </ul>`
          }
        </section>
      </div>
    </section>

    <section class="bg-[radial-gradient(ellipse_55%_45%_at_0%_20%,color-mix(in_srgb,#2f7a6b_18%,transparent),transparent_65%),linear-gradient(180deg,#121a18_0%,#0c1110_100%)] text-mist" aria-label="Recover">
      <div class="w-[min(1120px,calc(100%-2rem))] mx-auto py-[clamp(2.75rem,7vw,4.5rem)]">
        <section class="grid gap-6 lg:grid-cols-[minmax(14rem,0.9fr)_minmax(0,1.3fr)] lg:gap-10 lg:items-start" id="recover" aria-labelledby="recover-title">
          <div>
            <p class="m-0 text-[0.78rem] tracking-[0.14em] uppercase text-brass/80">03 · Recover</p>
            <h2 id="recover-title" class="mt-1.5 mb-3 font-display text-[clamp(1.8rem,4vw,2.4rem)] font-medium tracking-tight text-mist">Reassemble the secret</h2>
            <p class="m-0 max-w-md text-mist/75 leading-relaxed">
              The API verifies each share signature, then interpolates the secret from the selected fragments.
              Signatures only validate against the process that issued them.
            </p>
          </div>
          <div class="grid gap-4 p-5 rounded-2xl bg-ink-soft/90 border border-mist/10">
            <p class="m-0 text-[0.95rem] ${ready ? 'text-teal-bright/90' : 'text-mist/70'}">${escapeHtml(statusHint())}</p>
            <div>
              <button type="button" data-action="recover" class="${btnPrimary()}" ${ready ? '' : 'disabled'}>
                ${state.recoverBusy ? 'Recovering…' : 'Recover secret'}
              </button>
            </div>
            ${state.recoverError ? `<p class="m-0 p-3 rounded-lg bg-[#d97862]/20 text-[#f3c2b5] text-sm" role="alert">${escapeHtml(state.recoverError)}</p>` : ''}
            ${
              state.recovered
                ? `<div class="grid gap-3 animate-reveal" role="status">
                    <div class="flex flex-wrap gap-3 justify-between items-center">
                      <h3 class="m-0 font-display text-xl font-medium">Recovered secret</h3>
                      <div class="inline-flex gap-4">
                        <button type="button" data-action="toggle-reveal" class="${textBtn(true)}">${state.reveal ? 'Hide' : 'Reveal'}</button>
                        <button type="button" data-action="copy-secret" class="${textBtn(true)}">Copy</button>
                      </div>
                    </div>
                    <pre class="m-0 p-4 rounded-xl bg-black/35 text-mist font-mono text-[0.92rem] whitespace-pre-wrap break-words ${
                      state.reveal ? '' : 'blur-[7px] select-none'
                    }">${escapeHtml(state.recovered)}</pre>
                  </div>`
                : ''
            }
          </div>
        </section>
      </div>
    </section>
  </main>

  <footer class="px-4 md:px-8 pt-5 pb-8 bg-ink text-mist/60 text-sm text-center">
    <p class="m-0">
      TypeScript + Tailwind frontend for the
      <a class="text-brass" href="https://github.com/apeixinho/secretSharingFramework/tree/age/reactive-main-hardening-07a4" target="_blank" rel="noreferrer">reactive Secret Sharing API</a>
      · shares persist locally in this browser
    </p>
  </footer>
  `
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function syncSplitFormControls(): void {
  const errors = validateSplit()
  const invalid = Boolean(errors.k || errors.n || errors.secret)
  const submit = app!.querySelector<HTMLButtonElement>('#split-form button[type="submit"]')
  if (submit && !state.splitBusy) {
    submit.disabled = invalid
  }
  const counter = app!.querySelector<HTMLElement>('[data-secret-count]')
  if (counter) {
    counter.textContent = `${state.secret.length} / 300`
  }
}

function bindEvents() {
  app!.querySelector('#split-form')?.addEventListener('submit', (event) => {
    event.preventDefault()
    void onSplit()
  })

  // Form fields update state in place — no full-DOM remount on each keystroke.
  app!.querySelector<HTMLInputElement>('#threshold')?.addEventListener('input', (event) => {
    state.k = Number((event.target as HTMLInputElement).value)
    syncSplitFormControls()
  })
  app!.querySelector<HTMLInputElement>('#total-shares')?.addEventListener('input', (event) => {
    state.n = Number((event.target as HTMLInputElement).value)
    syncSplitFormControls()
  })
  app!.querySelector<HTMLTextAreaElement>('#secret')?.addEventListener('input', (event) => {
    state.secret = (event.target as HTMLTextAreaElement).value
    syncSplitFormControls()
  })
  app!.querySelector<HTMLTextAreaElement>('#import-json')?.addEventListener('input', (event) => {
    state.importText = (event.target as HTMLTextAreaElement).value
  })

  app!.querySelectorAll<HTMLElement>('[data-action]').forEach((el) => {
    el.addEventListener('click', (event) => {
      const action = el.dataset.action
      const index = Number(el.dataset.index)
      void handleAction(action, index, event)
    })
  })
}

async function handleAction(action: string | undefined, index: number, event: Event) {
  switch (action) {
    case 'refresh-health':
      setState({ health: await checkHealth() })
      break
    case 'toggle-import':
      setState({ importOpen: !state.importOpen, vaultError: null, vaultNotice: null })
      break
    case 'import-shares':
      try {
        setState({
          vault: importShares(state.importText),
          importOpen: false,
          importText: '',
          vaultNotice: 'Shares imported into the vault.',
          vaultError: null,
        })
      } catch (err) {
        setState({
          vaultError: err instanceof Error ? err.message : 'Could not import shares.',
          vaultNotice: null,
        })
      }
      break
    case 'export-vault':
      try {
        await navigator.clipboard.writeText(exportJson(state.vault))
        setState({ vaultNotice: 'Vault JSON copied to clipboard.', vaultError: null })
      } catch {
        setState({ vaultError: 'Could not copy vault JSON to clipboard.', vaultNotice: null })
      }
      break
    case 'clear-vault':
      setState({ vault: clearVault(), vaultNotice: 'Vault cleared from this browser.', vaultError: null })
      break
    case 'select-k':
      setState({ vault: selectThreshold(state.vault) })
      break
    case 'select-all':
      setState({ vault: selectAll(state.vault) })
      break
    case 'clear-selection':
      setState({ vault: clearSelection(state.vault) })
      break
    case 'toggle-share':
      event.preventDefault()
      setState({ vault: toggleShare(state.vault, index) })
      break
    case 'copy-share': {
      const share = state.vault.shares.find((item) => item.index === index)
      if (!share) return
      try {
        await navigator.clipboard.writeText(JSON.stringify(share, null, 2))
        setState({ copiedIndex: index })
        window.setTimeout(() => {
          if (state.copiedIndex === index) setState({ copiedIndex: null })
        }, 1400)
      } catch {
        setState({ vaultError: 'Could not copy to clipboard.', vaultNotice: null })
      }
      break
    }
    case 'recover':
      await onRecover()
      break
    case 'toggle-reveal':
      setState({ reveal: !state.reveal })
      break
    case 'copy-secret':
      if (state.recovered) {
        try {
          await navigator.clipboard.writeText(state.recovered)
        } catch {
          setState({ recoverError: 'Could not copy secret to clipboard.' })
        }
      }
      break
    default:
      break
  }
}

async function onSplit() {
  const errors = validateSplit()
  if (errors.k || errors.n || errors.secret) {
    setState({
      splitError: errors.secret || errors.n || errors.k,
      splitSuccess: null,
    })
    return
  }
  setState({ splitBusy: true, splitError: null, splitSuccess: null })
  try {
    const shares = await splitSecret({ k: state.k, n: state.n, secret: state.secret.trim() })
    setState({
      vault: replaceShares(shares, state.k, state.n),
      splitBusy: false,
      splitSuccess: `Created ${shares.length} signed shares. Any ${state.k} can reconstruct the secret.`,
    })
    document.getElementById('vault')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  } catch (err) {
    setState({
      splitBusy: false,
      splitError: err instanceof Error ? err.message : 'Split failed.',
    })
  }
}

async function onRecover() {
  setState({ recoverError: null, recovered: null, reveal: false })
  if (!canRecover()) {
    setState({ recoverError: statusHint() })
    return
  }
  setState({ recoverBusy: true })
  try {
    const secret = await recoverSecret(selectedShares(state.vault))
    setState({ recovered: secret, recoverBusy: false })
  } catch (err) {
    setState({
      recoverBusy: false,
      recoverError: err instanceof Error ? err.message : 'Recovery failed.',
    })
  }
}

function render(remount = true) {
  if (!remount) return

  app!.innerHTML = renderShell()
  bindEvents()
}

void checkHealth().then((health) => setState({ health }))
render()
