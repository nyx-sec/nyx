const BASE = '/api';
const CSRF_HEADER = 'X-Nyx-CSRF';
let csrfTokenPromise: Promise<string> | null = null;

export class ApiError extends Error {
  /**
   * Stable machine-readable code (matches backend `ApiError`'s `code` field).
   * Falls back to a synthetic value when the response was not structured,
   * `network` for fetch failures, `http_<status>` for plain-text responses.
   */
  public code: string;
  public detail?: unknown;

  constructor(
    status: number,
    message: string,
    code?: string,
    detail?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code ?? `http_${status}`;
    this.detail = detail;
  }

  public status: number;

  /** True when the failure was a network/abort, not an HTTP response. */
  isNetwork(): boolean {
    return this.status === 0;
  }
}

/** Build an ApiError from a non-OK Response, parsing a JSON error body if present. */
async function errorFromResponse(res: Response): Promise<ApiError> {
  const text = await res.text().catch(() => '');
  if (text) {
    try {
      const parsed = JSON.parse(text) as {
        error?: unknown;
        code?: unknown;
        detail?: unknown;
      };
      const msg =
        typeof parsed.error === 'string' && parsed.error.length > 0
          ? parsed.error
          : res.statusText || `HTTP ${res.status}`;
      const code = typeof parsed.code === 'string' ? parsed.code : undefined;
      return new ApiError(res.status, msg, code, parsed.detail);
    } catch {
      // Plain-text body, use as-is.
      return new ApiError(res.status, text);
    }
  }
  return new ApiError(res.status, res.statusText || `HTTP ${res.status}`);
}

async function getCsrfToken(): Promise<string> {
  if (!csrfTokenPromise) {
    csrfTokenPromise = fetch(`${BASE}/session`)
      .then(async (res) => {
        if (!res.ok) {
          throw await errorFromResponse(res);
        }

        const text = await res.text();
        const payload = text
          ? (JSON.parse(text) as { csrf_token?: unknown })
          : {};
        if (
          typeof payload.csrf_token !== 'string' ||
          payload.csrf_token.length === 0
        ) {
          throw new ApiError(500, 'Missing CSRF token', 'missing_csrf_token');
        }

        return payload.csrf_token;
      })
      .catch((error) => {
        csrfTokenPromise = null;
        throw error;
      });
  }

  return csrfTokenPromise;
}

function isMutatingMethod(method?: string): boolean {
  const upper = (method || 'GET').toUpperCase();
  return (
    upper === 'POST' ||
    upper === 'PUT' ||
    upper === 'PATCH' ||
    upper === 'DELETE'
  );
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const { headers: rawHeaders, ...rest } = opts;
  const url = `${BASE}${path}`;
  const headers: Record<string, string> = {
    ...(rawHeaders as Record<string, string>),
  };
  if (isMutatingMethod(rest.method)) {
    headers[CSRF_HEADER] = await getCsrfToken();
  }
  if (opts.body) {
    headers['Content-Type'] = 'application/json';
  }
  let res: Response;
  try {
    res = await fetch(url, {
      ...rest,
      headers,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw err;
    }
    const message =
      err instanceof Error ? err.message : 'Network request failed';
    throw new ApiError(0, message, 'network');
  }

  if (!res.ok) {
    throw await errorFromResponse(res);
  }

  // Handle empty responses
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { signal });
}

export function apiPost<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body != null ? JSON.stringify(body) : undefined,
    signal,
  });
}

export function apiPut<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
    body: body != null ? JSON.stringify(body) : undefined,
    signal,
  });
}

export function apiDelete<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(path, {
    method: 'DELETE',
    body: body != null ? JSON.stringify(body) : undefined,
    signal,
  });
}
