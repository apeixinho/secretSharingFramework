import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  clearSelection,
  clearVault,
  exportJson,
  importShares,
  meetsThreshold,
  normalizeShares,
  persistSnapshot,
  readStorage,
  replaceShares,
  selectAll,
  selectThreshold,
  selectedShares,
  toggleShare,
} from './vault'
import { STORAGE_KEY, type SecretShare } from './models'
import { checkHealth, recoverSecret, splitSecret } from './api'

const sampleShares: SecretShare[] = [
  { index: 1, share: '11', signature: 'sig-a' },
  { index: 2, share: '22', signature: 'sig-b' },
  { index: 3, share: '33', signature: 'sig-c' },
]

describe('vault', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('replaceShares selects the first k indexes', () => {
    const snapshot = replaceShares(sampleShares, 2, 3)
    expect(snapshot.threshold).toBe(2)
    expect(snapshot.totalShares).toBe(3)
    expect(snapshot.selectedIndexes).toEqual([1, 2])
    expect(meetsThreshold(snapshot)).toBe(true)
  })

  it('toggleShare adds and removes selection', () => {
    let snapshot = replaceShares(sampleShares, 2, 3)
    snapshot = toggleShare(snapshot, 3)
    expect(snapshot.selectedIndexes).toEqual([1, 2, 3])
    snapshot = toggleShare(snapshot, 1)
    expect(snapshot.selectedIndexes).toEqual([2, 3])
  })

  it('selectThreshold and selectAll update selection', () => {
    let snapshot = replaceShares(sampleShares, 2, 3)
    snapshot = clearSelection(snapshot)
    expect(meetsThreshold(snapshot)).toBe(false)
    snapshot = selectThreshold(snapshot)
    expect(snapshot.selectedIndexes).toEqual([1, 2])
    snapshot = selectAll(snapshot)
    expect(selectedShares(snapshot)).toHaveLength(3)
  })

  it('importShares accepts array and object forms', () => {
    const fromArray = importShares(JSON.stringify(sampleShares), 2)
    expect(fromArray.shares).toHaveLength(3)
    expect(fromArray.threshold).toBe(2)

    const fromObject = importShares(
      JSON.stringify({ threshold: 3, shares: sampleShares }),
    )
    expect(fromObject.threshold).toBe(3)
  })

  it('importShares rejects invalid JSON and invalid shares', () => {
    expect(() => importShares('{')).toThrow(/Invalid JSON/)
    expect(() => importShares(JSON.stringify({ hello: true }))).toThrow(/shares array/)
    expect(() =>
      importShares(JSON.stringify([{ index: 0, share: '1', signature: 'x' }])),
    ).toThrow(/invalid index/)
  })

  it('persistSnapshot and readStorage round-trip', () => {
    const snapshot = replaceShares(sampleShares, 2, 3)
    persistSnapshot(snapshot)
    expect(localStorage.getItem(STORAGE_KEY)).toBeTruthy()
    const restored = readStorage()
    expect(restored.shares).toEqual(sampleShares)
    expect(restored.selectedIndexes).toEqual([1, 2])
  })

  it('clearVault removes storage', () => {
    persistSnapshot(replaceShares(sampleShares, 2, 3))
    clearVault()
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull()
    expect(readStorage().shares).toEqual([])
  })

  it('exportJson includes threshold and shares', () => {
    const json = exportJson(replaceShares(sampleShares, 2, 3))
    expect(JSON.parse(json)).toMatchObject({
      threshold: 2,
      totalShares: 3,
      shares: sampleShares,
    })
  })

  it('normalizeShares coerces share values to strings', () => {
    const shares = normalizeShares([{ index: 1, share: 42, signature: 'sig' }])
    expect(shares[0]?.share).toBe('42')
  })
})

describe('api', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('splitSecret posts JSON and returns shares', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => sampleShares,
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await splitSecret({ k: 2, n: 3, secret: 'abc' })
    expect(result).toEqual(sampleShares)
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/splitSecret',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ k: 2, n: 3, secret: 'abc' }),
      }),
    )
  })

  it('recoverSecret returns text body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        text: async () => 'recovered-secret',
      }),
    )
    await expect(recoverSecret(sampleShares.slice(0, 2))).resolves.toBe('recovered-secret')
  })

  it('maps 400 and network failures to user errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ error: 'bad request detail' }),
      }),
    )
    await expect(splitSecret({ k: 1, n: 1, secret: 'abc' })).rejects.toThrow('bad request detail')

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(splitSecret({ k: 1, n: 1, secret: 'abc' })).rejects.toThrow(/Cannot reach/)
  })

  it('maps 403 recover failures to signature message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        text: async () => '',
      }),
    )
    await expect(recoverSecret(sampleShares)).rejects.toThrow(/signature verification failed/)
  })

  it('checkHealth returns online/offline', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'UP' }),
      }),
    )
    await expect(checkHealth()).resolves.toBe('online')

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    await expect(checkHealth()).resolves.toBe('offline')
  })
})
