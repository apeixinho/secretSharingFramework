import { Component, computed, inject, signal } from '@angular/core';
import { SecretSharingApiService } from '../../core/services/secret-sharing-api.service';
import { ShareVaultService } from '../../core/services/share-vault.service';

@Component({
  selector: 'ssf-recover-secret',
  templateUrl: './recover-secret.html',
  styleUrl: './recover-secret.scss',
})
export class RecoverSecret {
  private readonly api = inject(SecretSharingApiService);
  readonly vault = inject(ShareVaultService);

  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly recoveredSecret = signal<string | null>(null);
  readonly revealSecret = signal(false);

  readonly canRecover = computed(
    () => this.vault.selectedCount() > 0 && this.vault.meetsThreshold() && !this.busy(),
  );

  readonly statusHint = computed(() => {
    if (!this.vault.hasShares()) {
      return 'Load shares into the vault before recovering.';
    }
    if (this.vault.selectedCount() === 0) {
      return 'Select at least one share to recover.';
    }
    if (!this.vault.meetsThreshold()) {
      const threshold = this.vault.threshold();
      return threshold == null
        ? 'Select more shares to recover.'
        : `Select at least ${threshold} shares (currently ${this.vault.selectedCount()}).`;
    }
    return `Ready to recover with ${this.vault.selectedCount()} share(s).`;
  });

  recover(): void {
    this.error.set(null);
    this.recoveredSecret.set(null);
    this.revealSecret.set(false);

    if (!this.canRecover()) {
      this.error.set(this.statusHint());
      return;
    }

    const shares = this.vault.selectedShares();
    this.busy.set(true);

    this.api.recoverSecret(shares).subscribe({
      next: (secret) => {
        this.recoveredSecret.set(secret);
        this.busy.set(false);
      },
      error: (err: unknown) => {
        this.error.set(err instanceof Error ? err.message : 'Recovery failed.');
        this.busy.set(false);
      },
    });
  }

  toggleReveal(): void {
    this.revealSecret.update((value) => !value);
  }

  async copySecret(): Promise<void> {
    const secret = this.recoveredSecret();
    if (!secret) {
      return;
    }
    await navigator.clipboard.writeText(secret);
  }
}
