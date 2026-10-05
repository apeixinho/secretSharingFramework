import { TestBed } from '@angular/core/testing';
import { ShareVaultService } from './share-vault.service';
import { SecretShare } from '../models/secret-share';

const STORAGE_KEY = 'ssf.share-vault.v1';

const sampleShares: SecretShare[] = [
  { index: 1, share: '11', signature: 'sig-a' },
  { index: 2, share: '22', signature: 'sig-b' },
  { index: 3, share: '33', signature: 'sig-c' },
];

describe('ShareVaultService', () => {
  let vault: ShareVaultService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [ShareVaultService],
    });
    vault = TestBed.inject(ShareVaultService);
  });

  afterEach(() => {
    localStorage.clear();
  });

  it('replaceShares selects the first k indexes', () => {
    vault.replaceShares(sampleShares, 2, 3);
    expect(vault.threshold()).toBe(2);
    expect(vault.totalShares()).toBe(3);
    expect(vault.selectedIndexes()).toEqual([1, 2]);
    expect(vault.meetsThreshold()).toBe(true);
  });

  it('toggleShare adds and removes selection', () => {
    vault.replaceShares(sampleShares, 2, 3);
    vault.toggleShare(3);
    expect(vault.selectedIndexes()).toEqual([1, 2, 3]);
    vault.toggleShare(1);
    expect(vault.selectedIndexes()).toEqual([2, 3]);
  });

  it('selectThreshold and selectAll update selection', () => {
    vault.replaceShares(sampleShares, 2, 3);
    vault.clearSelection();
    expect(vault.meetsThreshold()).toBe(false);
    vault.selectThreshold();
    expect(vault.selectedIndexes()).toEqual([1, 2]);
    vault.selectAll();
    expect(vault.selectedShares()).toHaveLength(3);
  });

  it('importShares accepts array and object forms', () => {
    vault.importShares(JSON.stringify(sampleShares), 2);
    expect(vault.shares()).toHaveLength(3);
    expect(vault.threshold()).toBe(2);

    vault.clearVault();
    vault.importShares(JSON.stringify({ threshold: 3, shares: sampleShares }));
    expect(vault.threshold()).toBe(3);
  });

  it('importShares rejects invalid shares', () => {
    expect(() => vault.importShares(JSON.stringify({ hello: true }))).toThrow(/shares array/);
    expect(() =>
      vault.importShares(JSON.stringify([{ index: 0, share: '1', signature: 'x' }])),
    ).toThrow(/invalid index/);
  });

  it('exportJson includes threshold and shares', () => {
    vault.replaceShares(sampleShares, 2, 3);
    expect(JSON.parse(vault.exportJson())).toMatchObject({
      threshold: 2,
      totalShares: 3,
      shares: sampleShares,
    });
  });

  it('clearVault empties state and storage', () => {
    vault.replaceShares(sampleShares, 2, 3);
    expect(vault.hasShares()).toBe(true);
    vault.clearVault();
    expect(vault.shares()).toEqual([]);
    expect(vault.hasShares()).toBe(false);
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('restores snapshot from localStorage on construction', () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        version: 1,
        threshold: 2,
        totalShares: 3,
        shares: sampleShares,
        selectedIndexes: [1, 2],
        updatedAt: new Date().toISOString(),
      }),
    );

    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [ShareVaultService],
    });
    const restored = TestBed.inject(ShareVaultService);

    expect(restored.shares()).toEqual(sampleShares);
    expect(restored.selectedIndexes()).toEqual([1, 2]);
    expect(restored.threshold()).toBe(2);
  });
});
