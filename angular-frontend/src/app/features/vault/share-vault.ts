import { Component, inject, signal } from '@angular/core';
import { ShareVaultService } from '../../core/services/share-vault.service';

@Component({
  selector: 'ssf-share-vault',
  templateUrl: './share-vault.html',
  styleUrl: './share-vault.scss',
})
export class ShareVault {
  readonly vault = inject(ShareVaultService);

  readonly importOpen = signal(false);
  readonly importText = signal('');
  readonly notice = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly copiedIndex = signal<number | null>(null);

  toggleImport(): void {
    this.importOpen.update((open) => !open);
    this.error.set(null);
    this.notice.set(null);
  }

  importShares(): void {
    this.error.set(null);
    this.notice.set(null);
    try {
      this.vault.importShares(this.importText());
      this.importOpen.set(false);
      this.importText.set('');
      this.notice.set('Shares imported into the vault.');
    } catch (err) {
      this.error.set(err instanceof Error ? err.message : 'Could not import shares.');
    }
  }

  async copyShare(index: number): Promise<void> {
    const share = this.vault.shares().find((item) => item.index === index);
    if (!share) {
      return;
    }
    await navigator.clipboard.writeText(JSON.stringify(share, null, 2));
    this.copiedIndex.set(index);
    window.setTimeout(() => {
      if (this.copiedIndex() === index) {
        this.copiedIndex.set(null);
      }
    }, 1400);
  }

  async exportVault(): Promise<void> {
    await navigator.clipboard.writeText(this.vault.exportJson());
    this.notice.set('Vault JSON copied to clipboard.');
    this.error.set(null);
  }

  clearVault(): void {
    this.vault.clearVault();
    this.notice.set('Vault cleared from this browser.');
    this.error.set(null);
  }
}
