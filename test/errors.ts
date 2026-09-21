// Error taxonomy — the contract consumers will branch on.
//
// The point of these classes is that a caller can tell "the credential was
// denied" (re-claim) from "not enough nodes answered" (retry) WITHOUT regexing a
// message. So the assertions here are mostly about types, fields, and the
// instanceof chain staying intact — those are the things a refactor can silently
// break while every message still looks right.
//
// Run: tsx test/errors.ts

import {
  AuthDeniedError,
  httpError,
  isAuthDenied,
  isRetryable,
  TasraError,
  TasraHttpError,
  NodeUnreachableError,
  SlotRotatedError,
  ThresholdNotMetError,
} from '../src/errors.ts'
import {CommitteeAuthorizeError} from '../src/committee/client.ts'
import {DcqlMalformedError} from '../src/auth/oid4vp.ts'
import {VerifierAgentSessionError} from '../src/verifier-agent/index.ts'
import {fetchAndAssembleKey} from '../src/keys/node-client.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean): void {
  if (cond) passed++
  else failures.push(name)
}

// ─── instanceof chain ────────────────────────────────────────────────────────
// Consumers catch at whatever altitude suits them; every level must work.
{
  const denied = new AuthDeniedError({status: 403, url: 'http://n/v1/shards/key', body: 'rule denied'})
  ok('AuthDeniedError instanceof TasraHttpError', denied instanceof TasraHttpError)
  ok('AuthDeniedError instanceof TasraError', denied instanceof TasraError)
  ok('AuthDeniedError instanceof Error', denied instanceof Error)
  ok('name is the subclass name', denied.name === 'AuthDeniedError')

  const threshold = new ThresholdNotMetError({got: 1, need: 3})
  ok('ThresholdNotMetError instanceof TasraError', threshold instanceof TasraError)
  ok('ThresholdNotMetError is NOT an http error', !(threshold instanceof TasraHttpError))
}

// ─── retryability ────────────────────────────────────────────────────────────
// The coarse signal for callers that don't enumerate types. Getting these
// backwards means a caller either retry-loops a dead credential or gives up on a
// node that was merely restarting.
{
  ok('401 is not retryable', !new TasraHttpError({status: 401, url: 'u'}).retryable)
  ok('403 is not retryable', !new TasraHttpError({status: 403, url: 'u'}).retryable)
  ok('404 is not retryable', !new TasraHttpError({status: 404, url: 'u'}).retryable)
  ok('429 IS retryable', new TasraHttpError({status: 429, url: 'u'}).retryable)
  ok('503 IS retryable', new TasraHttpError({status: 503, url: 'u'}).retryable)
  ok('AuthDeniedError is never retryable', !new AuthDeniedError({status: 401, url: 'u'}).retryable)
  ok('NodeUnreachableError IS retryable', new NodeUnreachableError({url: 'u'}).retryable)
  ok('ThresholdNotMetError defaults to retryable', new ThresholdNotMetError({got: 0, need: 3}).retryable)
  ok(
    'ThresholdNotMetError can be pinned non-retryable',
    !new ThresholdNotMetError({got: 0, need: 3, retryable: false}).retryable,
  )
  ok('SlotRotatedError IS retryable', new SlotRotatedError({expected: 1, actual: 2}).retryable)

  ok('isRetryable(503)', isRetryable(new TasraHttpError({status: 503, url: 'u'})))
  ok('isRetryable(401) is false', !isRetryable(new TasraHttpError({status: 401, url: 'u'})))
  // A bug in consumer code is not something to retry.
  ok('isRetryable(TypeError) is false', !isRetryable(new TypeError('boom')))
  ok('isRetryable(undefined) is false', !isRetryable(undefined))
}

// ─── isAuthDenied is status-keyed, not class-keyed ───────────────────────────
// CommitteeAuthorizeError predates the taxonomy and keeps its own name, so a
// class check would miss it. Consumers must still be able to spot a 403 there.
{
  ok('isAuthDenied(AuthDeniedError)', isAuthDenied(new AuthDeniedError({status: 401, url: 'u'})))
  ok(
    'isAuthDenied(CommitteeAuthorizeError 403) — subclass with its own name',
    isAuthDenied(new CommitteeAuthorizeError(403, 'not drawn')),
  )
  ok(
    'isAuthDenied is false for a 500',
    !isAuthDenied(new TasraHttpError({status: 500, url: 'u'})),
  )
  ok('isAuthDenied is false for a non-http error', !isAuthDenied(new ThresholdNotMetError({got: 0, need: 2})))
  ok(
    'CommitteeAuthorizeError still carries .status',
    new CommitteeAuthorizeError(403, 'x').status === 403,
  )
  ok(
    'CommitteeAuthorizeError is a TasraHttpError',
    new CommitteeAuthorizeError(403, 'x') instanceof TasraHttpError,
  )
}

// ─── structured fields ───────────────────────────────────────────────────────
{
  const e = new TasraHttpError({status: 502, url: 'http://node-1/v1/shards/key', body: 'upstream gone'})
  ok('http error keeps status', e.status === 502)
  ok('http error keeps url', e.url === 'http://node-1/v1/shards/key')
  ok('http error keeps body', e.body === 'upstream gone')
  ok('default message includes url, status, body', /node-1.*502.*upstream gone/.test(e.message))

  const t = new ThresholdNotMetError({got: 2, need: 3, reasons: ['n1 → HTTP 500', 'n2 unreachable']})
  ok('threshold keeps got/need', t.got === 2 && t.need === 3)
  ok('threshold keeps per-participant reasons', t.reasons.length === 2)
  ok('threshold message names both counts', t.message.includes('2/3'))
  ok('threshold message includes the reasons', t.message.includes('n2 unreachable'))

  const r = new SlotRotatedError({expected: 4, actual: 7, slotId: '0x' + 'ab'.repeat(32)})
  ok('rotated keeps both epochs', r.expected === 4 && r.actual === 7)
  ok('rotated message names both epochs', /epoch 4/.test(r.message) && /epoch 7/.test(r.message))
}

// ─── httpError() classifies by status and truncates the body ─────────────────
{
  const mk = (status: number, body: string): Response =>
    new Response(body, {status, statusText: 'x'})

  const denied = await httpError(mk(403, 'dcql denied'), 'http://v/v1/redeem', 'redeem')
  ok('httpError(403) → AuthDeniedError', denied instanceof AuthDeniedError)
  ok('httpError uses the label in the message', denied.message.startsWith('redeem → HTTP 403'))
  ok('httpError carries the body', denied.body === 'dcql denied')

  const generic = await httpError(mk(500, 'kaboom'), 'http://v/x')
  ok('httpError(500) → TasraHttpError, not AuthDenied', !(generic instanceof AuthDeniedError))
  ok('httpError(500) is retryable', generic.retryable)
  ok('httpError falls back to the url as label', generic.message.startsWith('http://v/x → HTTP 500'))

  // 200 chars, so a node returning an HTML error page can't flood a log line.
  const long = await httpError(mk(400, 'z'.repeat(5000)), 'http://v/x')
  ok('httpError truncates the body to 200 chars', long.body.length === 200)
}

// ─── fetchAndAssembleKey: the regression this taxonomy was built for ─────────
// Previously every per-node reason was collected and then thrown away, so a DNS
// failure and a cold DKG produced the same 'No shards collected' string.
{
  const realFetch = globalThis.fetch
  const urls = ['http://n1', 'http://n2', 'http://n3']

  try {
    // (a) all nodes deny → not retryable, and says so.
    globalThis.fetch = (async () => new Response('expired jwt', {status: 401})) as typeof fetch
    let caught: unknown
    try {
      await fetchAndAssembleKey({urls, jwt: 'stale'}, '0x' + 'cd'.repeat(32))
    } catch (e) {
      caught = e
    }
    ok('all-denied → ThresholdNotMetError', caught instanceof ThresholdNotMetError)
    ok('all-denied is NOT retryable', caught instanceof ThresholdNotMetError && !caught.retryable)
    ok(
      'all-denied reasons carry every node',
      caught instanceof ThresholdNotMetError && caught.reasons.length === urls.length,
    )
    ok(
      'all-denied reasons carry the node bodies',
      caught instanceof ThresholdNotMetError && caught.reasons.every(r => r.includes('expired jwt')),
    )
    ok(
      'all-denied message tells the caller to re-claim',
      caught instanceof Error && /re-claim/.test(caught.message),
    )

    // (b) transport failures → retryable, reasons preserved and distinguishable.
    globalThis.fetch = (async () => {
      throw new TypeError('fetch failed: ECONNREFUSED')
    }) as unknown as typeof fetch
    let net: unknown
    try {
      await fetchAndAssembleKey({urls, jwt: 'fine'}, '0x' + 'cd'.repeat(32))
    } catch (e) {
      net = e
    }
    ok('unreachable → ThresholdNotMetError', net instanceof ThresholdNotMetError)
    ok('unreachable IS retryable', net instanceof ThresholdNotMetError && net.retryable)
    ok(
      'unreachable reasons are distinguishable from a denial',
      net instanceof ThresholdNotMetError && net.reasons.every(r => /ECONNREFUSED/.test(r)),
    )
  } finally {
    globalThis.fetch = realFetch
  }
}

// ─── every SDK-thrown error is a TasraError ──────────────────────────────
// The DCQL and verifier-agent errors used to extend bare Error, so the one check the README
// tells consumers to write — `instanceof TasraError` — missed them.
{
  const dcql = new DcqlMalformedError('rule is not an object')
  ok('DcqlMalformedError instanceof TasraError', dcql instanceof TasraError)
  ok('DcqlMalformedError keeps its name', dcql.name === 'DcqlMalformedError')
  ok('DcqlMalformedError is never retryable', !isRetryable(dcql))

  const timeout = new VerifierAgentSessionError('timeout', 'sess-1234567890abcdef', 'poll: gave up')
  ok('VerifierAgentSessionError instanceof TasraError', timeout instanceof TasraError)
  ok('VerifierAgentSessionError keeps its name', timeout.name === 'VerifierAgentSessionError')
  ok('VerifierAgentSessionError carries kind + correlation', timeout.kind === 'timeout' && timeout.correlation === 'sess-1234567890abcdef')
  ok('VerifierAgentSessionError timeout IS retryable', isRetryable(timeout))
  ok('VerifierAgentSessionError unavailable IS retryable', isRetryable(new VerifierAgentSessionError('unavailable', 's', 'verifierAgent down', 503)))
  ok('VerifierAgentSessionError refused is NOT retryable', !isRetryable(new VerifierAgentSessionError('refused', 's', 'verifier said no')))
  ok('VerifierAgentSessionError protocol is NOT retryable', !isRetryable(new VerifierAgentSessionError('protocol', 's', 'bad reply', 404)))
  ok('VerifierAgentSessionError cancelled is NOT retryable', !isRetryable(new VerifierAgentSessionError('cancelled', 's', 'aborted')))
}

if (failures.length > 0) {
  console.error(`✗ errors: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ errors: ${passed} checks passed`)
