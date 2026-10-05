import { STORAGE_KEY, type SecretShare, type ShareVaultSnapshot } from './models'

export const emptySnapshot = (): ShareVaultSnapshot => ({
  version: 1,
  threshold: null,
  totalShares: null,
  shares: [],
  selectedIndexes: [],
  updatedAt: new Date(0).toISOString(),
})

export function readStorage(): ShareVaultSnapshot {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) {
      return emptySnapshot()
    }
    const parsed = JSON.parse(raw) as Partial<ShareVaultSnapshot>
    if (!Array.isArray(parsed.shares)) {
      return emptySnapshot()
    }
    return {
      version: 1,
      threshold: typeof parsed.threshold === 'number' ? parsed.threshold : null,
      totalShares:
        typeof parsed.totalShares === 'number' ? parsed.totalShares : parsed.shares.length,
      shares: normalizeShares(parsed.shares),
      selectedIndexes: Array.isArray(parsed.selectedIndexes)
        ? parsed.selectedIndexes.filter((value): value is number => typeof value === 'number')
        : parsed.shares.map((share) => share.index),
      updatedAt:
        typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
    }
  } catch {
    return emptySnapshot()
  }
}

export function persistSnapshot(snapshot: ShareVaultSnapshot): void {
  if (snapshot.updatedAt === new Date(0).toISOString() && snapshot.shares.length === 0) {
    return
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot))
}

export function replaceShares(
  shares: SecretShare[],
  threshold: number,
  totalShares: number,
): ShareVaultSnapshot {
  const indexes = shares.map((share) => share.index)
  return {
    version: 1,
    threshold,
    totalShares,
    shares: structuredClone(shares),
    selectedIndexes: indexes.slice(0, threshold),
    updatedAt: new Date().toISOString(),
  }
}

export function toggleShare(snapshot: ShareVaultSnapshot, index: number): ShareVaultSnapshot {
  const selected = new Set(snapshot.selectedIndexes)
  if (selected.has(index)) {
    selected.delete(index)
  } else {
    selected.add(index)
  }
  return {
    ...snapshot,
    selectedIndexes: [...selected].sort((a, b) => a - b),
    updatedAt: new Date().toISOString(),
  }
}

export function selectAll(snapshot: ShareVaultSnapshot): ShareVaultSnapshot {
  return {
    ...snapshot,
    selectedIndexes: snapshot.shares.map((share) => share.index),
    updatedAt: new Date().toISOString(),
  }
}

export function selectThreshold(snapshot: ShareVaultSnapshot): ShareVaultSnapshot {
  const count = snapshot.threshold ?? snapshot.shares.length
  return {
    ...snapshot,
    selectedIndexes: snapshot.shares.slice(0, count).map((share) => share.index),
    updatedAt: new Date().toISOString(),
  }
}

export function clearSelection(snapshot: ShareVaultSnapshot): ShareVaultSnapshot {
  return {
    ...snapshot,
    selectedIndexes: [],
    updatedAt: new Date().toISOString(),
  }
}

export function clearVault(): ShareVaultSnapshot {
  localStorage.removeItem(STORAGE_KEY)
  return emptySnapshot()
}

export function importShares(raw: string, threshold?: number | null): ShareVaultSnapshot {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw) as unknown
  } catch {
    throw new Error('Invalid JSON. Paste a share array or an object with a shares field.')
  }
  const shares = normalizeShares(parsed)

  let inferredThreshold = threshold ?? null
  if (
    inferredThreshold == null &&
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    typeof (parsed as { threshold?: unknown }).threshold === 'number'
  ) {
    inferredThreshold = (parsed as { threshold: number }).threshold
  }
  if (inferredThreshold == null) {
    inferredThreshold = Math.min(shares.length, Math.max(2, Math.ceil(shares.length * 0.6)))
  }

  return replaceShares(shares, inferredThreshold, shares.length)
}

export function exportJson(snapshot: ShareVaultSnapshot): string {
  return JSON.stringify(
    {
      threshold: snapshot.threshold,
      totalShares: snapshot.totalShares,
      shares: snapshot.shares,
    },
    null,
    2,
  )
}

export function selectedShares(snapshot: ShareVaultSnapshot): SecretShare[] {
  const selected = new Set(snapshot.selectedIndexes)
  return snapshot.shares.filter((share) => selected.has(share.index))
}

export function meetsThreshold(snapshot: ShareVaultSnapshot): boolean {
  const count = selectedShares(snapshot).length
  if (snapshot.threshold == null) {
    return count > 0
  }
  return count >= snapshot.threshold
}

export function normalizeShares(value: unknown): SecretShare[] {
  const list = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { shares?: unknown }).shares)
      ? (value as { shares: unknown[] }).shares
      : null

  if (!list) {
    throw new Error('Expected a JSON array of shares, or an object with a shares array.')
  }

  return list.map((item, position) => {
    if (!item || typeof item !== 'object') {
      throw new Error(`Share at position ${position + 1} is invalid.`)
    }
    const record = item as Record<string, unknown>
    const index = Number(record['index'])
    const share = record['share']
    const signature = record['signature']

    if (!Number.isInteger(index) || index < 1) {
      throw new Error(`Share at position ${position + 1} has an invalid index.`)
    }
    if (share == null || String(share).trim() === '') {
      throw new Error(`Share ${index} is missing a share value.`)
    }
    if (typeof signature !== 'string' || !signature.trim()) {
      throw new Error(`Share ${index} is missing a signature.`)
    }

    return {
      index,
      share: String(share),
      signature,
    }
  })
}
