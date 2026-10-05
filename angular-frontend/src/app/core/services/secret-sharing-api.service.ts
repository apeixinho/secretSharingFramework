import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Service, inject, signal } from '@angular/core';
import { Observable, catchError, map, of, tap, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  ApiHealthStatus,
  SecretShare,
  SplitSecretRequest,
} from '../models/secret-share';

@Service()
export class SecretSharingApiService {
  private readonly http = inject(HttpClient);

  readonly healthStatus = signal<ApiHealthStatus>('unknown');

  splitSecret(request: SplitSecretRequest): Observable<SecretShare[]> {
    return this.http
      .post<SecretShare[]>(`${environment.apiBaseUrl}/splitSecret`, request)
      .pipe(catchError((error) => throwError(() => this.toUserError(error, 'split'))));
  }

  recoverSecret(shares: SecretShare[]): Observable<string> {
    return this.http
      .post(`${environment.apiBaseUrl}/recoverSecret`, shares, {
        responseType: 'text',
      })
      .pipe(catchError((error) => throwError(() => this.toUserError(error, 'recover'))));
  }

  checkHealth(): Observable<ApiHealthStatus> {
    return this.http.get<{ status?: string }>(environment.healthUrl).pipe(
      map((body) => (body?.status === 'UP' ? 'online' : 'offline')),
      catchError(() => of<ApiHealthStatus>('offline')),
      tap((status) => this.healthStatus.set(status)),
    );
  }

  private toUserError(error: unknown, action: 'split' | 'recover'): Error {
    if (error instanceof HttpErrorResponse) {
      const payload = error.error;
      let detail = '';

      if (typeof payload === 'string' && payload.trim()) {
        try {
          const parsed = JSON.parse(payload) as { error?: string; message?: string };
          detail = parsed.error ?? parsed.message ?? payload;
        } catch {
          detail = payload;
        }
      } else if (payload && typeof payload === 'object') {
        const record = payload as { error?: string; message?: string };
        detail = record.error ?? record.message ?? '';
      }

      if (error.status === 0) {
        return new Error(
          'Cannot reach the Secret Sharing API. Start the backend on port 8080 and retry.',
        );
      }

      if (error.status === 403 && action === 'recover') {
        return new Error(
          detail ||
            'Share signature verification failed. Shares must come from the same API process that issued them.',
        );
      }

      if (error.status === 400) {
        return new Error(detail || 'The request was rejected. Check threshold, share count, and secret length.');
      }

      return new Error(detail || `Request failed with status ${error.status}.`);
    }

    return error instanceof Error ? error : new Error('Unexpected error talking to the API.');
  }
}
