import { Service, computed, effect, signal } from '@angular/core';
import { SecretShare, ShareVaultSnapshot } from '../models/secret-share';

const STORAGE_KEY = 'ssf.share-vault.v1';

const emptySnapshot = (): ShareVaultSnapshot => ({
  version: 1,
  threshold: null,
  totalShares: null,
  shares: [],
  selectedIndexes: [],
  updatedAt: new Date(0).toISOString(),
});

@Service()
export class ShareVaultService {
  private readonly snapshot = signal<ShareVaultSnapshot>(this.readStorage());

  readonly shares = computed(() => this.snapshot().shares);
  readonly threshold = computed(() => this.snapshot().threshold);
  readonly totalShares = computed(() => this.snapshot().totalShares);
  readonly selectedIndexes = computed(() => this.snapshot().selectedIndexes);
  readonly updatedAt = computed(() => this.snapshot().updatedAt);
  readonly hasShares = computed(() => this.shares().length > 0);
  readonly selectedShares = computed(() => {
    const selected = new Set(this.selectedIndexes());
    return this.shares().filter((share) => selected.has(share.index));
  });
  readonly selectedCount = computed(() => this.selectedShares().length);
  readonly meetsThreshold = computed(() => {
    const threshold = this.threshold();
    if (threshold == null) {
      return this.selectedCount() > 0;
    }
    return this.selectedCount() >= threshold;
  });

  constructor() {
    effect(() => {
      const current = this.snapshot();
      if (current.updatedAt === new Date(0).toISOString() && current.shares.length === 0) {
        return;
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
    });
  }

  replaceShares(shares: SecretShare[], threshold: number, totalShares: number): void {
    const indexes = shares.map((share) => share.index);
    this.snapshot.set({
      version: 1,
      threshold,
      totalShares,
      shares: structuredClone(shares),
      selectedIndexes: indexes.slice(0, threshold),
      updatedAt: new Date().toISOString(),
    });
  }

  toggleShare(index: number): void {
    this.snapshot.update((current) => {
      const selected = new Set(current.selectedIndexes);
      if (selected.has(index)) {
        selected.delete(index);
      } else {
        selected.add(index);
      }
      return {
        ...current,
        selectedIndexes: [...selected].sort((a, b) => a - b),
        updatedAt: new Date().toISOString(),
      };
    });
  }

  selectAll(): void {
    this.snapshot.update((current) => ({
      ...current,
      selectedIndexes: current.shares.map((share) => share.index),
      updatedAt: new Date().toISOString(),
    }));
  }

  selectThreshold(): void {
    this.snapshot.update((current) => {
      const count = current.threshold ?? current.shares.length;
      return {
        ...current,
        selectedIndexes: current.shares.slice(0, count).map((share) => share.index),
        updatedAt: new Date().toISOString(),
      };
    });
  }

  clearSelection(): void {
    this.snapshot.update((current) => ({
      ...current,
      selectedIndexes: [],
      updatedAt: new Date().toISOString(),
    }));
  }

  clearVault(): void {
    localStorage.removeItem(STORAGE_KEY);
    this.snapshot.set(emptySnapshot());
  }

  importShares(raw: string, threshold?: number | null): void {
    const parsed = JSON.parse(raw) as unknown;
    const shares = this.normalizeShares(parsed);

    let inferredThreshold = threshold ?? null;
    if (
      inferredThreshold == null &&
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      typeof (parsed as { threshold?: unknown }).threshold === 'number'
    ) {
      inferredThreshold = (parsed as { threshold: number }).threshold;
    }
    if (inferredThreshold == null) {
      inferredThreshold = Math.min(shares.length, Math.max(2, Math.ceil(shares.length * 0.6)));
    }

    this.replaceShares(shares, inferredThreshold, shares.length);
  }

  exportJson(): string {
    const current = this.snapshot();
    return JSON.stringify(
      {
        threshold: current.threshold,
        totalShares: current.totalShares,
        shares: current.shares,
      },
      null,
      2,
    );
  }

  isSelected(index: number): boolean {
    return this.selectedIndexes().includes(index);
  }

  private readStorage(): ShareVaultSnapshot {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return emptySnapshot();
      }
      const parsed = JSON.parse(raw) as Partial<ShareVaultSnapshot>;
      if (!Array.isArray(parsed.shares)) {
        return emptySnapshot();
      }
      return {
        version: 1,
        threshold: typeof parsed.threshold === 'number' ? parsed.threshold : null,
        totalShares: typeof parsed.totalShares === 'number' ? parsed.totalShares : parsed.shares.length,
        shares: this.normalizeShares(parsed.shares),
        selectedIndexes: Array.isArray(parsed.selectedIndexes)
          ? parsed.selectedIndexes.filter((value): value is number => typeof value === 'number')
          : parsed.shares.map((share) => share.index),
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
      };
    } catch {
      return emptySnapshot();
    }
  }

  private normalizeShares(value: unknown): SecretShare[] {
    const list = Array.isArray(value)
      ? value
      : value && typeof value === 'object' && Array.isArray((value as { shares?: unknown }).shares)
        ? (value as { shares: unknown[] }).shares
        : null;

    if (!list) {
      throw new Error('Expected a JSON array of shares, or an object with a shares array.');
    }

    return list.map((item, position) => {
      if (!item || typeof item !== 'object') {
        throw new Error(`Share at position ${position + 1} is invalid.`);
      }
      const record = item as Record<string, unknown>;
      const index = Number(record['index']);
      const share = record['share'];
      const signature = record['signature'];

      if (!Number.isInteger(index) || index < 1) {
        throw new Error(`Share at position ${position + 1} has an invalid index.`);
      }
      if (share == null || String(share).trim() === '') {
        throw new Error(`Share ${index} is missing a share value.`);
      }
      if (typeof signature !== 'string' || !signature.trim()) {
        throw new Error(`Share ${index} is missing a signature.`);
      }

      return {
        index,
        share: String(share),
        signature,
      };
    });
  }
}
