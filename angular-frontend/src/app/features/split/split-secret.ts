import { Component, inject, signal } from '@angular/core';
import {
  FormField,
  form,
  max,
  maxLength,
  min,
  minLength,
  required,
  submit,
  validate,
} from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { SecretSharingApiService } from '../../core/services/secret-sharing-api.service';
import { ShareVaultService } from '../../core/services/share-vault.service';

interface SplitModel {
  k: number | null;
  n: number | null;
  secret: string;
}

@Component({
  selector: 'ssf-split-secret',
  imports: [FormField],
  templateUrl: './split-secret.html',
  styleUrl: './split-secret.scss',
})
export class SplitSecret {
  private readonly api = inject(SecretSharingApiService);
  private readonly vault = inject(ShareVaultService);

  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly successMessage = signal<string | null>(null);

  readonly model = signal<SplitModel>({
    k: 3,
    n: 5,
    secret: '',
  });

  readonly splitForm = form(this.model, (path) => {
    required(path.k, { message: 'Threshold is required.' });
    min(path.k, 1, { message: 'Threshold must be at least 1.' });
    max(path.k, 60, { message: 'Threshold cannot exceed 60.' });

    required(path.n, { message: 'Share count is required.' });
    min(path.n, 1, { message: 'Share count must be at least 1.' });
    max(path.n, 60, { message: 'Share count cannot exceed 60.' });

    required(path.secret, { message: 'Secret is required.' });
    minLength(path.secret, 3, { message: 'Secret must be at least 3 characters.' });
    maxLength(path.secret, 300, { message: 'Secret cannot exceed 300 characters.' });

    validate(path.secret, ({ value }) => {
      if (value().trim().length === 0) {
        return { kind: 'whitespace', message: 'Secret cannot be only whitespace.' };
      }
      return null;
    });

    validate(path.n, ({ value, valueOf }) => {
      const k = valueOf(path.k);
      const n = value();
      if (k != null && n != null && n < k) {
        return {
          kind: 'n-lt-k',
          message: 'Share count (n) must be greater than or equal to threshold (k).',
        };
      }
      return null;
    });
  });

  onSubmit(event: Event): void {
    event.preventDefault();
    this.error.set(null);
    this.successMessage.set(null);

    submit(this.splitForm, {
      action: async () => {
        const { k, n, secret } = this.model();
        if (k == null || n == null) {
          return;
        }

        this.busy.set(true);
        try {
          const shares = await firstValueFrom(
            this.api.splitSecret({ k, n, secret: secret.trim() }),
          );
          this.vault.replaceShares(shares, k, n);
          this.successMessage.set(
            `Created ${shares.length} signed shares. Any ${k} can reconstruct the secret.`,
          );
          document.getElementById('vault')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (err) {
          this.error.set(err instanceof Error ? err.message : 'Split failed.');
        } finally {
          this.busy.set(false);
        }
      },
    });
  }
}
