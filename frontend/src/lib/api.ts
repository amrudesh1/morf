// Thin API client. Base URL is relative (/api) so nginx proxies to the backend
// in Docker and Vite's dev proxy handles local dev. An optional X-API-Key is
// supported for when the backend enforces auth (off in local today).
import type {
  JobStatusResponse,
  Pattern,
  PatternFile,
  PatternListResponse,
  PatternTestResponse,
  UploadResponse,
} from '@/types'

const API_BASE = '/api'

let apiKey: string | null = null
/** Set/clear the X-API-Key sent with requests (for when backend auth is on). */
export function setApiKey(key: string | null) {
  apiKey = key
}
function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const h: Record<string, string> = { ...(extra ?? {}) }
  if (apiKey) h['X-API-Key'] = apiKey
  return h
}

/** A network/HTTP failure that carries the backend's error message when present. */
export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json()
    if (body && typeof body.error === 'string') return body.error
  } catch {
    /* ignore */
  }
  return `Request failed (${res.status})`
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new ApiError(await parseError(res), res.status)
  return res.json() as Promise<T>
}

// --- Scan ------------------------------------------------------------------
export async function uploadFile(file: File, signal?: AbortSignal): Promise<UploadResponse> {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: form,
    headers: authHeaders(),
    signal,
  })
  return json<UploadResponse>(res)
}

/** Fetch a job's status/result. Returns the raw JobStatusResponse (or throws). */
export async function getJobResult(jobId: string, signal?: AbortSignal): Promise<JobStatusResponse> {
  const res = await fetch(`${API_BASE}/results/${encodeURIComponent(jobId)}`, {
    headers: authHeaders(),
    signal,
  })
  return json<JobStatusResponse>(res)
}

// --- Patterns --------------------------------------------------------------
export const patternsApi = {
  list: () => fetch(`${API_BASE}/patterns`, { headers: authHeaders() }).then(json<PatternListResponse>),
  getFile: (filename: string) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}`, { headers: authHeaders() }).then(
      json<{ filename: string; patterns: Pattern[] }>,
    ),
  createFile: (filename: string, patterns: Pattern[]) =>
    fetch(`${API_BASE}/patterns`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ filename, patterns }),
    }).then(json<{ message: string }>),
  deleteFile: (filename: string) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}`, {
      method: 'DELETE',
      headers: authHeaders(),
    }).then(json<{ message: string }>),
  addPattern: (filename: string, pattern: Pattern) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}/patterns`, {
      method: 'PUT',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(pattern),
    }).then(json<{ message: string }>),
  updatePattern: (filename: string, name: string, pattern: Pattern) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}/patterns/${encodeURIComponent(name)}`, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(pattern),
    }).then(json<{ message: string }>),
  deletePattern: (filename: string, name: string) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}/patterns/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: authHeaders(),
    }).then(json<{ message: string }>),
  setEnabled: (filename: string, name: string, enabled: boolean) =>
    fetch(
      `${API_BASE}/patterns/${encodeURIComponent(filename)}/patterns/${encodeURIComponent(name)}/enable`,
      {
        method: 'PATCH',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ enabled }),
      },
    ).then(json<{ message: string }>),
  test: (filename: string, patternName: string, sampleText: string) =>
    fetch(`${API_BASE}/patterns/${encodeURIComponent(filename)}/test`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ pattern_name: patternName, sample_text: sampleText }),
    }).then(json<PatternTestResponse>),
}

export type { PatternFile }
