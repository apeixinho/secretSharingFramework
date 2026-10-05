import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { SecretSharingApiService } from './secret-sharing-api.service';
import { SecretShare } from '../models/secret-share';
import { environment } from '../../../environments/environment';

const sampleShares: SecretShare[] = [
  { index: 1, share: '11', signature: 'sig-a' },
  { index: 2, share: '22', signature: 'sig-b' },
];

describe('SecretSharingApiService', () => {
  let api: SecretSharingApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), SecretSharingApiService],
    });
    api = TestBed.inject(SecretSharingApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('splitSecret posts JSON and returns shares', () => {
    let result: SecretShare[] | undefined;
    api.splitSecret({ k: 2, n: 3, secret: 'abc' }).subscribe((shares) => {
      result = shares;
    });

    const req = httpMock.expectOne(`${environment.apiBaseUrl}/splitSecret`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ k: 2, n: 3, secret: 'abc' });
    req.flush(sampleShares);

    expect(result).toEqual(sampleShares);
  });

  it('recoverSecret returns text body', () => {
    let result: string | undefined;
    api.recoverSecret(sampleShares).subscribe((secret) => {
      result = secret;
    });

    const req = httpMock.expectOne(`${environment.apiBaseUrl}/recoverSecret`);
    expect(req.request.method).toBe('POST');
    req.flush('recovered-secret');

    expect(result).toBe('recovered-secret');
  });

  it('maps 400 responses to user errors', () => {
    let error: Error | undefined;
    api.splitSecret({ k: 1, n: 1, secret: 'abc' }).subscribe({
      error: (err: Error) => {
        error = err;
      },
    });

    const req = httpMock.expectOne(`${environment.apiBaseUrl}/splitSecret`);
    req.flush({ error: 'bad request detail' }, { status: 400, statusText: 'Bad Request' });

    expect(error?.message).toBe('bad request detail');
  });

  it('maps 403 recover failures to signature message', () => {
    let error: Error | undefined;
    api.recoverSecret(sampleShares).subscribe({
      error: (err: Error) => {
        error = err;
      },
    });

    const req = httpMock.expectOne(`${environment.apiBaseUrl}/recoverSecret`);
    req.flush('', { status: 403, statusText: 'Forbidden' });

    expect(error?.message).toMatch(/signature verification failed/);
  });

  it('maps network failures to offline message', () => {
    let error: Error | undefined;
    api.splitSecret({ k: 1, n: 1, secret: 'abc' }).subscribe({
      error: (err: Error) => {
        error = err;
      },
    });

    const req = httpMock.expectOne(`${environment.apiBaseUrl}/splitSecret`);
    req.error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });

    expect(error?.message).toMatch(/Cannot reach/);
  });

  it('checkHealth returns online and offline', () => {
    let online: string | undefined;
    api.checkHealth().subscribe((status) => {
      online = status;
    });
    httpMock.expectOne(environment.healthUrl).flush({ status: 'UP' });
    expect(online).toBe('online');
    expect(api.healthStatus()).toBe('online');

    let offline: string | undefined;
    api.checkHealth().subscribe((status) => {
      offline = status;
    });
    httpMock.expectOne(environment.healthUrl).error(new ProgressEvent('error'));
    expect(offline).toBe('offline');
    expect(api.healthStatus()).toBe('offline');
  });
});
