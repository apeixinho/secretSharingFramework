import {
  API_BASE_URL,
  HEALTH_URL,
  type ApiHealthStatus,
  type SecretShare,
  type SplitSecretRequest,
} from './models'

const OFFLINE_MESSAGE =
  'Cannot reach the Secret Sharing API. Start the backend on port 8080 and retry.'

export async function splitSecret(request: SplitSecretRequest): Promise<SecretShare[]> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/splitSecret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    })
  } catch {
    throw new Error(OFFLINE_MESSAGE)
  }
  if (!response.ok) {
    throw await toUserError(response, 'split')
  }
  return (await response.json()) as SecretShare[]
}

export async function recoverSecret(shares: SecretShare[]): Promise<string> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/recoverSecret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(shares),
    })
  } catch {
    throw new Error(OFFLINE_MESSAGE)
  }
  if (!response.ok) {
    throw await toUserError(response, 'recover')
  }
  return response.text()
}

export async function checkHealth(): Promise<ApiHealthStatus> {
  try {
    const response = await fetch(HEALTH_URL)
    if (!response.ok) {
      return 'offline'
    }
    const body = (await response.json()) as { status?: string }
    return body.status === 'UP' ? 'online' : 'offline'
  } catch {
    return 'offline'
  }
}

async function toUserError(response: Response, action: 'split' | 'recover'): Promise<Error> {
  const detail = await readErrorDetail(response)

  if (response.status === 403 && action === 'recover') {
    return new Error(
      detail ||
        'Share signature verification failed. Shares must come from the same API process that issued them.',
    )
  }
  if (response.status === 400) {
    return new Error(
      detail || 'The request was rejected. Check threshold, share count, and secret length.',
    )
  }
  return new Error(detail || `Request failed with status ${response.status}.`)
}

async function readErrorDetail(response: Response): Promise<string> {
  const raw = await response.text()
  if (!raw.trim()) {
    return ''
  }
  try {
    const payload: unknown = JSON.parse(raw)
    if (typeof payload === 'string') {
      return payload
    }
    if (payload && typeof payload === 'object') {
      const record = payload as { error?: string; message?: string }
      return record.error ?? record.message ?? raw
    }
  } catch {
    return raw
  }
  return raw
}
