const API_BASE = import.meta.env.VITE_API_URL ?? ''

export class ApiError extends Error {
  status: number
  code?: string
  traceId?: string
  retryable: boolean

  constructor(
    status: number,
    message: string,
    options?: { code?: string; traceId?: string }
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = options?.code
    this.traceId = options?.traceId
    this.retryable = status === 0 || status === 429 ||
      status === 502 || status === 503 || status === 504
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      credentials: 'include'
    })
  } catch {
    throw new ApiError(
      0,
      '서버에 연결할 수 없습니다. 네트워크 연결과 서버 실행 상태를 확인해주세요.',
      { code: 'NETWORK_ERROR' }
    )
  }

  if (!response.ok) {
    let message = `요청 실패 (HTTP ${response.status})`
    let code: string | undefined
    let traceId: string | undefined
    try {
      const payload = await response.json() as Record<string, unknown>
      const errors = Array.isArray(payload.errors)
        ? payload.errors.map(String).join(', ')
        : undefined
      message = String(payload.detail || payload.message || errors || message)
      code = typeof payload.code === 'string' ? payload.code : undefined
      traceId = typeof payload.traceId === 'string' ? payload.traceId : undefined
    } catch {
      // JSON 오류 본문이 아니면 기본 메시지를 사용합니다.
    }
    throw new ApiError(response.status, message, { code, traceId })
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  put: <T>(path: string, body?: unknown) => request<T>(path, {
    method: 'PUT',
    body: body === undefined ? undefined : JSON.stringify(body)
  }),
  post: <T>(path: string, body?: unknown) => request<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body)
  }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  postForm: <T>(path: string, body: FormData) => request<T>(path, { method: 'POST', body }),
  downloadUrl: (path: string) => `${API_BASE}${path}`
}
