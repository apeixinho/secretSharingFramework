import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import type { SecretShare, ShareVaultSnapshot } from '../lib/models'
import {
  clearSelection as clearSelectionFn,
  clearVault as clearVaultFn,
  exportJson,
  importShares as importSharesFn,
  meetsThreshold,
  persistSnapshot,
  readStorage,
  replaceShares,
  selectAll as selectAllFn,
  selectThreshold as selectThresholdFn,
  selectedShares,
  toggleShare as toggleShareFn,
} from '../lib/vault'

interface VaultContextValue {
  snapshot: ShareVaultSnapshot
  hasShares: boolean
  selectedCount: number
  selected: SecretShare[]
  ready: boolean
  replace: (shares: SecretShare[], threshold: number, totalShares: number) => void
  toggle: (index: number) => void
  selectAll: () => void
  selectThreshold: () => void
  clearSelection: () => void
  clearVault: () => void
  importShares: (raw: string) => void
  exportJson: () => string
  isSelected: (index: number) => boolean
}

const VaultContext = createContext<VaultContextValue | null>(null)

export function VaultProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<ShareVaultSnapshot>(() => readStorage())

  useEffect(() => {
    persistSnapshot(snapshot)
  }, [snapshot])

  const replace = useCallback((shares: SecretShare[], threshold: number, totalShares: number) => {
    setSnapshot(replaceShares(shares, threshold, totalShares))
  }, [])

  const toggle = useCallback((index: number) => {
    setSnapshot((current) => toggleShareFn(current, index))
  }, [])

  const selectAll = useCallback(() => {
    setSnapshot((current) => selectAllFn(current))
  }, [])

  const selectThreshold = useCallback(() => {
    setSnapshot((current) => selectThresholdFn(current))
  }, [])

  const clearSelection = useCallback(() => {
    setSnapshot((current) => clearSelectionFn(current))
  }, [])

  const clearVault = useCallback(() => {
    setSnapshot(clearVaultFn())
  }, [])

  const importShares = useCallback((raw: string) => {
    setSnapshot(importSharesFn(raw))
  }, [])

  const value = useMemo<VaultContextValue>(
    () => ({
      snapshot,
      hasShares: snapshot.shares.length > 0,
      selectedCount: selectedShares(snapshot).length,
      selected: selectedShares(snapshot),
      ready: meetsThreshold(snapshot),
      replace,
      toggle,
      selectAll,
      selectThreshold,
      clearSelection,
      clearVault,
      importShares,
      exportJson: () => exportJson(snapshot),
      isSelected: (index: number) => snapshot.selectedIndexes.includes(index),
    }),
    [
      snapshot,
      replace,
      toggle,
      selectAll,
      selectThreshold,
      clearSelection,
      clearVault,
      importShares,
    ],
  )

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>
}

export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext)
  if (!ctx) {
    throw new Error('useVault must be used within VaultProvider')
  }
  return ctx
}
