import {httpError} from '../errors.js'
// Off-chain read clients for the live fleet (keykeeper-node + verifier).
//
// Unlike the browser-oriented nodeClient.ts (which routes through a CORS proxy),
// these are direct server-to-server reads for the explorer's aggregator: a node
// or verifier base URL in, a typed status object out, with a built-in timeout.
// All endpoints here are the public, unauthenticated read surface.

export interface FetchOpts {
  /** Per-request timeout in ms (default 4000). */
  timeoutMs?: number
  /** Bearer JWT, for the few authenticated reads (metering/audit). */
  jwt?: string
}

async function fetchJson<T>(url: string, opts: FetchOpts = {}): Promise<T> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 4000)
  try {
    const headers: Record<string, string> = {}
    if (opts.jwt) headers.Authorization = `Bearer ${opts.jwt}`
    const res = await fetch(url, {signal: ctrl.signal, headers})
    if (!res.ok) throw await httpError(res, url)
    return (await res.json()) as T
  } finally {
    clearTimeout(t)
  }
}

async function fetchText(url: string, opts: FetchOpts = {}): Promise<string> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 4000)
  try {
    const res = await fetch(url, {signal: ctrl.signal})
    if (!res.ok) throw await httpError(res, url)
    return await res.text()
  } finally {
    clearTimeout(t)
  }
}

const trim = (u: string) => u.replace(/\/$/, '')

// ── keykeeper-node ────────────────────────────────────────────────────────

export interface NodeInfo {
  peer_id?: string
  node_identifier?: number
  version?: string
  build_profile?: string
  uptime_secs?: number
  connected_peers?: number | null
  rate_limit_enabled?: boolean
  admin_scope_enabled?: boolean
  [k: string]: unknown
}

export interface KeySlotSummary {
  key_slot_id: string
  threshold_k: number
  threshold_n: number
  epoch: number
  group_public_key?: string | null
  dcql_rule?: string | null
  mode?: string
  created_at?: string
  last_signed_at?: string | null
  [k: string]: unknown
}

export interface KeyListReply {
  slots: KeySlotSummary[]
  [k: string]: unknown
}

export interface SignedHeartbeat {
  operator: string
  epoch: number
  pubkey: string
  signature: string
  [k: string]: unknown
}

export interface MeteringReply {
  key_slot_id: string
  since?: string
  until?: string
  total: number
  by_subject?: Array<{subject: string; count: number}>
  attestation?: unknown
  [k: string]: unknown
}

export const nodeApi = {
  info: (base: string, o?: FetchOpts) =>
    fetchJson<NodeInfo>(`${trim(base)}/v1/info`, o),
  health: (base: string, o?: FetchOpts) =>
    fetchJson<{status: string}>(`${trim(base)}/health`, o),
  readyz: (base: string, o?: FetchOpts) =>
    fetchJson<{status: string; component?: string}>(`${trim(base)}/readyz`, o),
  keys: (base: string, o?: FetchOpts) =>
    fetchJson<KeyListReply>(`${trim(base)}/v1/keys`, {...o}),
  keySlot: (base: string, id: string, o?: FetchOpts) =>
    fetchJson<KeySlotSummary>(`${trim(base)}/v1/keys/${id}`, o),
  keySlotPublic: (base: string, id: string, o?: FetchOpts) =>
    fetchJson<{group_public_key?: string; epoch?: number}>(
      `${trim(base)}/v1/keys/${id}/public`,
      o,
    ),
  heartbeat: (base: string, o?: FetchOpts) =>
    fetchJson<SignedHeartbeat>(`${trim(base)}/v1/heartbeat`, o),
  metering: (base: string, id: string, o?: FetchOpts) =>
    fetchJson<MeteringReply>(`${trim(base)}/v1/metering/${id}`, o),
  metrics: (base: string, o?: FetchOpts) =>
    fetchText(`${trim(base)}/metrics`, o),
}

// ── verifier ──────────────────────────────────────────────────────

export interface VerifierInfo {
  version?: string
  uptime_secs?: number
  jwt_ttl_secs?: number
  rate_limit_enabled?: boolean
  [k: string]: unknown
}

export const verifierApi = {
  info: (base: string, o?: FetchOpts) =>
    fetchJson<VerifierInfo>(`${trim(base)}/v1/info`, o),
  health: (base: string, o?: FetchOpts) =>
    fetchJson<{status: string}>(`${trim(base)}/health`, o),
  metrics: (base: string, o?: FetchOpts) =>
    fetchText(`${trim(base)}/metrics`, o),
}

/**
 * Parse a Prometheus text exposition into a flat map of `metric{labels}` →
 * value. Good enough for the explorer's dashboards (counters/gauges); skips
 * HELP/TYPE/comment lines and histograms' bucket internals are left as-is.
 */
export function parsePrometheus(text: string): Record<string, number> {
  const out: Record<string, number> = {}
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const sp = line.lastIndexOf(' ')
    if (sp < 0) continue
    const key = line.slice(0, sp).trim()
    const val = Number(line.slice(sp + 1).trim())
    if (Number.isFinite(val)) out[key] = val
  }
  return out
}
