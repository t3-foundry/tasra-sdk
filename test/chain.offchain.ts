// The off-chain read clients — the node/verifier status surface an aggregator polls.
//
// `src/chain/offchain.ts` had no coverage at all. It is two dozen one-line endpoint
// wrappers over two fetch helpers, so the things worth asserting are the three that are not
// visible from a return value:
//
//   • WHICH URL each wrapper builds. Same bug class as the chain client's typed readers: a
//     copy-pasted path across twenty near-identical one-liners compiles, type-checks, and is
//     only wrong against a live node — where it looks like the node is broken.
//   • the TIMEOUT. These are server-to-server reads inside an aggregator loop, so a helper
//     that does not actually abort turns one unreachable node into a stalled poll cycle.
//     The header advertises a 4 s default; nothing checked that it fires at all.
//   • WHO gets the bearer token. `fetchJson` sends `Authorization` when a jwt is passed;
//     `fetchText` — the `/metrics` path — does NOT, whatever the caller passes. That
//     asymmetry is silent, so a caller assuming an authenticated metrics read gets an
//     unauthenticated one.
//
// `parsePrometheus` is pure, and its one real hazard is splitting on the wrong space: a
// metric with labels has spaces inside the label set, so the VALUE is after the LAST space.
//
// Run: tsx test/chain.offchain.ts — exits non-zero on any failure.

import {nodeApi, parsePrometheus, verifierApi} from '../src/chain/offchain.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual)
  const b = JSON.stringify(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}

const NODE = 'http://keeper-1:8080'
const VERIFIER = 'http://verifier-0:8080'
const SLOT = `0x${'cd'.repeat(32)}`

// ─── the stub ─────────────────────────────────────────────────────────────────
interface Seen {
  url: string
  headers: Record<string, string>
  signal?: AbortSignal
}
const seen: Seen[] = []
/** Status to answer with (200 = a normal reply). */
let status = 200
/** Delay the reply by this many ms, to let a timeout fire. */
let delayMs = 0
/** Reply as text rather than JSON (the /metrics shape). */
const TEXT_BODY = '# HELP up 1\n# TYPE up gauge\nup 1\n'

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  seen.push({url: u, headers: (init?.headers ?? {}) as Record<string, string>, signal: init?.signal ?? undefined})
  if (delayMs > 0) {
    // Honour the abort signal the helper passed, the way a real fetch does.
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, delayMs)
      init?.signal?.addEventListener('abort', () => {
        clearTimeout(timer)
        const err = new Error('The operation was aborted')
        err.name = 'AbortError'
        reject(err)
      })
    })
  }
  if (status !== 200) {
    return {ok: false, status, text: async () => `refused with ${status}`} as unknown as Response
  }
  return {
    ok: true,
    status: 200,
    json: async () => ({status: 'ok', url: u}),
    text: async () => TEXT_BODY,
  } as unknown as Response
}) as typeof globalThis.fetch

const lastUrl = (): string => seen[seen.length - 1]?.url ?? ''

try {
  // ─── every endpoint builds the right URL ────────────────────────────────────
  {
    // A trailing slash on the base must not produce a double slash — some routers 404 on it.
    const cases: Array<[string, () => Promise<unknown>, string]> = [
      ['nodeApi.info', () => nodeApi.info(NODE), `${NODE}/v1/info`],
      ['nodeApi.info (trailing slash base)', () => nodeApi.info(`${NODE}/`), `${NODE}/v1/info`],
      ['nodeApi.health', () => nodeApi.health(NODE), `${NODE}/health`],
      ['nodeApi.readyz', () => nodeApi.readyz(NODE), `${NODE}/readyz`],
      ['nodeApi.keys', () => nodeApi.keys(NODE), `${NODE}/v1/keys`],
      ['nodeApi.keySlot', () => nodeApi.keySlot(NODE, SLOT), `${NODE}/v1/keys/${SLOT}`],
      ['nodeApi.keySlotPublic', () => nodeApi.keySlotPublic(NODE, SLOT), `${NODE}/v1/keys/${SLOT}/public`],
      ['nodeApi.heartbeat', () => nodeApi.heartbeat(NODE), `${NODE}/v1/heartbeat`],
      ['nodeApi.metering', () => nodeApi.metering(NODE, SLOT), `${NODE}/v1/metering/${SLOT}`],
      ['nodeApi.metrics', () => nodeApi.metrics(NODE), `${NODE}/metrics`],
      ['verifierApi.info', () => verifierApi.info(VERIFIER), `${VERIFIER}/v1/info`],
      ['verifierApi.health', () => verifierApi.health(VERIFIER), `${VERIFIER}/health`],
      ['verifierApi.metrics', () => verifierApi.metrics(VERIFIER), `${VERIFIER}/metrics`],
    ]
    const wrong: string[] = []
    for (const [label, run, want] of cases) {
      seen.length = 0
      try {
        await run()
      } catch (error) {
        wrong.push(`${label} threw: ${error instanceof Error ? error.message : String(error)}`)
        continue
      }
      if (lastUrl() !== want) wrong.push(`${label}: requested ${lastUrl()}, expected ${want}`)
    }
    eq(`all ${cases.length} endpoints request the documented path`, wrong, [])
    // ⚠ /health and /readyz are NOT under /v1 while the rest are. A "tidy-up" that moved
    // them would break every liveness probe, so the distinction is pinned explicitly.
    seen.length = 0
    await nodeApi.health(NODE)
    ok('health is served outside the /v1 prefix', !lastUrl().includes('/v1/'))
    await nodeApi.readyz(NODE)
    ok('readyz is served outside the /v1 prefix', !lastUrl().includes('/v1/'))
    await nodeApi.info(NODE)
    ok('info IS under /v1', lastUrl().endsWith('/v1/info'))
  }

  // ─── the bearer token goes only where it is read ─────────────────────────────
  {
    seen.length = 0
    await nodeApi.metering(NODE, SLOT, {jwt: 'the.jwt.token'})
    eq('a jwt becomes an Authorization header on an authenticated read', seen[0]?.headers.Authorization, 'Bearer the.jwt.token')
    seen.length = 0
    await nodeApi.info(NODE)
    eq('no jwt means no Authorization header at all', Object.keys(seen[0]?.headers ?? {}), [])
    // ⚠ /metrics goes through fetchText, which sends NO headers. A caller passing a jwt here
    // gets an unauthenticated request — worth knowing rather than assuming.
    seen.length = 0
    await nodeApi.metrics(NODE, {jwt: 'the.jwt.token'})
    eq('a metrics read sends no Authorization even when a jwt is supplied', Object.keys(seen[0]?.headers ?? {}), [])
    seen.length = 0
    await verifierApi.metrics(VERIFIER, {jwt: 'the.jwt.token'})
    eq('the same holds for the verifier metrics read', Object.keys(seen[0]?.headers ?? {}), [])
  }

  // ─── the built-in timeout ───────────────────────────────────────────────────
  {
    // Every call carries an abort signal; without one the timeout could not fire.
    seen.length = 0
    await nodeApi.info(NODE)
    ok('a request carries an abort signal', seen[0]?.signal instanceof AbortSignal)
    ok('the signal is not already aborted', seen[0]?.signal?.aborted === false)

    // ⚠ The reason this matters: an aggregator polls many nodes in a loop, so one
    // unreachable node must cost its timeout and not the cycle. Asserted by delaying the
    // reply past a short timeout and requiring the call to reject.
    delayMs = 5_000
    const started = Date.now()
    await rejectsWith('a slow JSON read is aborted by the timeout', /abort/i, () =>
      nodeApi.info(NODE, {timeoutMs: 30}),
    )
    ok('…and it gave up quickly rather than waiting out the reply', Date.now() - started < 2_000)
    await rejectsWith('a slow TEXT read is aborted too', /abort/i, () => nodeApi.metrics(NODE, {timeoutMs: 30}))
    delayMs = 0

    // A reply inside the budget must NOT be aborted.
    delayMs = 5
    const info = await nodeApi.info(NODE, {timeoutMs: 1_000})
    ok('a reply inside the budget succeeds', (info as {status?: string}).status === 'ok')
    delayMs = 0
  }

  // ─── failure reporting ──────────────────────────────────────────────────────
  {
    // The URL is in the error: an aggregator polling twenty nodes needs to know WHICH one.
    status = 503
    await rejectsWith('a JSON read reports the status', /503/, () => nodeApi.info(NODE))
    await rejectsWith('…and names the URL that failed', new RegExp(NODE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), () => nodeApi.readyz(NODE))
    await rejectsWith('a TEXT read reports the status too', /503/, () => nodeApi.metrics(NODE))
    await rejectsWith('the verifier client reports the same way', /503/, () => verifierApi.info(VERIFIER))
    status = 200
  }

  // ─── the shapes come back typed ─────────────────────────────────────────────
  {
    eq('a text read returns the body verbatim', await nodeApi.metrics(NODE), TEXT_BODY)
    ok('a JSON read returns the parsed body', (await nodeApi.health(NODE)).status === 'ok')
  }
} finally {
  globalThis.fetch = realFetch
}

// ─── parsePrometheus (pure) ───────────────────────────────────────────────────
{
  const text = [
    '# HELP keykeeper_signs_total Signatures produced',
    '# TYPE keykeeper_signs_total counter',
    'keykeeper_signs_total 42',
    '',
    '   ',
    'keykeeper_up 1',
    'keykeeper_latency_seconds_bucket{le="0.5",slot="abc"} 7',
    'keykeeper_build_info{version="0.1.0",profile="release"} 1',
    'keykeeper_nan_metric NaN',
    'keykeeper_no_value',
    '# a trailing comment',
  ].join('\n')
  const m = parsePrometheus(text)

  eq('a plain counter is parsed', m.keykeeper_signs_total, 42)
  eq('a gauge is parsed', m.keykeeper_up, 1)
  // ⚠ The value is after the LAST space, because a label set contains spaces of its own.
  // Splitting on the FIRST space would make the key `keykeeper_latency_seconds_bucket{le="0.5",`
  // and the value NaN — silently dropping every labelled metric.
  eq('a labelled metric keeps its whole label set in the key', m['keykeeper_latency_seconds_bucket{le="0.5",slot="abc"}'], 7)
  eq('a multi-label metric parses too', m['keykeeper_build_info{version="0.1.0",profile="release"}'], 1)

  ok('HELP lines are skipped', !Object.keys(m).some(k => k.startsWith('#')))
  ok('TYPE lines are skipped', !('TYPE' in m) && !Object.keys(m).some(k => k.includes('TYPE')))
  ok('a trailing comment is skipped', !Object.keys(m).some(k => k.includes('trailing')))
  // A non-finite value is dropped rather than stored as NaN, which would poison any
  // arithmetic a dashboard does on it.
  ok('a NaN value is dropped, not stored', !('keykeeper_nan_metric' in m))
  // A line with no space at all has no value to read.
  ok('a line with no value is skipped', !('keykeeper_no_value' in m))
  eq('exactly the four real metrics survive', Object.keys(m).length, 4)

  // Robustness on the inputs a real exposition throws at it.
  eq('an empty input yields an empty map', Object.keys(parsePrometheus('')).length, 0)
  eq('CRLF line endings are handled', parsePrometheus('a_metric 5\r\nb_metric 6\r\n').b_metric, 6)
  eq('leading whitespace on a line is tolerated', parsePrometheus('   spaced_metric 3').spaced_metric, 3)
  eq('a float value is kept as a float', parsePrometheus('ratio 0.25').ratio, 0.25)
  eq('a negative value is kept', parsePrometheus('delta -7').delta, -7)
  // Prometheus writes +Inf for an unbounded bucket; it is not finite, so it is dropped.
  ok('+Inf is dropped as non-finite', !('inf_metric' in parsePrometheus('inf_metric +Inf')))
  // Scientific notation is valid in the exposition format.
  eq('scientific notation parses', parsePrometheus('big 1.5e3').big, 1500)
  // A later line for the same key wins, matching a last-write-wins read of a stream.
  eq('a repeated key takes the last value', parsePrometheus('dup 1\ndup 2').dup, 2)
}

if (failures.length > 0) {
  console.error(`✗ chain.offchain: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ chain.offchain: ${passed} checks passed`)
