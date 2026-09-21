// The node key client — the two calls every session makes, and how they fail.
//
// `fetchMpk` and `fetchAndAssembleKey` are on the critical path of every openSession, so what
// they do with a FAILURE is most of their value. Two classifications carry real weight:
//
//   • A 200 with an EMPTY `group_public_key` is a known-but-unkeyed slot: the DKG has not
//     finished. That is transient and must be marked retryable, unlike a 404 — a caller that
//     treated it as a hard failure would give up on a slot that is seconds from being ready.
//
//   • When EVERY node rejects the JWT with 401/403 the error must be NON-retryable and say to
//     re-claim. Retrying the identical token cannot succeed, and a generic "threshold not met"
//     reads as transient and gets retry-looped — a denied user hammering the fleet forever.
//     A MIXED failure (one denial, one network error) is retryable, because the non-auth half
//     might clear.
//
// Either way the per-node reasons ride along on the error rather than being discarded, so a
// caller can tell a DNS failure from a cold DKG.
//
// Run: tsx test/keys.node-client.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {fetchAndAssembleKey, fetchMpk} from '../src/keys/node-client.ts'
import {ThresholdNotMetError, TasraError, isRetryable} from '../src/errors.ts'
import {scalarToLe} from '../src/crypto/kem.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const json = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x))
  const a = json(actual)
  const b = json(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
/** Run and return whatever was thrown, for inspecting an error's fields. */
async function thrown(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run()
    return null
  } catch (error) {
    return error
  }
}

const G2 = bls12_381.G2.ProjectivePoint
const {Fr} = bls12_381.fields
const hex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

const SLOT_BARE = 'cd'.repeat(32)
const SLOT_0X = `0x${SLOT_BARE}`
const msk = Fr.create(BigInt('0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe'))
const mpkBytes = G2.BASE.multiply(msk).toRawBytes(true)

// ─── the node stub ────────────────────────────────────────────────────────────
interface Seen {
  url: string
  method: string
  headers: Record<string, string>
  body: string
}
const seen: Seen[] = []
/** Per-node behaviour for the shard endpoint, keyed by the node's number. */
type ShardMode = 'serve' | 401 | 403 | 500 | 'network' | 'non-error'
const shardMode = new Map<number, ShardMode>()
/** What /public answers with. */
let publicMode: 'serve' | 'no-key' | 'no-epoch' | 404 = 'serve'

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  seen.push({
    url: u,
    method: String(init?.method ?? 'GET'),
    headers: (init?.headers ?? {}) as Record<string, string>,
    body: String(init?.body ?? ''),
  })
  const json = (o: unknown): Response => ({ok: true, status: 200, json: async () => o} as unknown as Response)
  const fail = (status: number, text: string): Response =>
    ({ok: false, status, text: async () => text, json: async () => ({error: text})} as unknown as Response)

  if (u.includes('/public')) {
    if (publicMode === 404) return fail(404, 'unknown key slot')
    // ⚠ A known-but-unkeyed slot answers 200 with an EMPTY key — the DKG has not finished.
    if (publicMode === 'no-key') return json({group_public_key: '', epoch: 0})
    if (publicMode === 'no-epoch') return json({group_public_key: `0x${hex(mpkBytes)}`})
    return json({group_public_key: `0x${hex(mpkBytes)}`, epoch: 7})
  }
  if (u.includes('/v1/shards/key')) {
    const n = Number(/node-(\d+)/.exec(u)?.[1] ?? -1)
    const mode = shardMode.get(n) ?? 'serve'
    if (mode === 'network') throw new Error(`connect ECONNREFUSED to node-${n}`)
    // A rejection that is NOT an Error at all — a patched fetch or a bundler shim can do this.
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
    if (mode === 'non-error') return Promise.reject(`node-${n} hung up`)
    if (mode !== 'serve') return fail(mode, `node-${n} says no`)
    // A 1-of-1 slot: Lagrange over the single identifier {1} has λ = 1, so the assembled key
    // is the shard itself.
    return json({identifier: 1, shard: Buffer.from(scalarToLe(msk)).toString('base64'), epoch: 7})
  }
  return fail(404, `no route ${u}`)
}) as typeof globalThis.fetch

try {
  // ─── fetchMpk ───────────────────────────────────────────────────────────────
  {
    seen.length = 0
    const withPrefix = await fetchMpk('http://node-0', SLOT_0X)
    eq('the group key is decoded', hex(withPrefix.mpkBytes), hex(mpkBytes))
    eq('the epoch comes back', withPrefix.epoch, 7)
    eq('the request path carries the 0x form', seen[0]?.url, `http://node-0/v1/keys/${SLOT_0X}/public`)

    // ⚠ A BARE slot id is accepted and normalised — the doc says "with or without the 0x
    // prefix", and both must produce the same URL or half the callers 404.
    seen.length = 0
    await fetchMpk('http://node-0', SLOT_BARE)
    eq('a bare slot id is normalised to the 0x form', seen[0]?.url, `http://node-0/v1/keys/${SLOT_0X}/public`)
    // A trailing slash on the node url must not double up.
    seen.length = 0
    await fetchMpk('http://node-0/', SLOT_0X)
    ok('a trailing slash on the node url is normalised', seen[0]?.url === `http://node-0/v1/keys/${SLOT_0X}/public`)

    // An absent epoch defaults to 0 rather than becoming undefined/NaN — it feeds an epoch
    // comparison, where NaN would read as "always stale".
    publicMode = 'no-epoch'
    eq('a reply with no epoch defaults to 0', (await fetchMpk('http://node-0', SLOT_0X)).epoch, 0)

    // ⚠ THE COLD-DKG CASE. 200 with an empty key is a slot that exists but has no key yet.
    // It must be RETRYABLE and say so, unlike a 404 — a caller that gave up here would give up
    // on a slot that is seconds from being ready.
    publicMode = 'no-key'
    const cold = await thrown(() => fetchMpk('http://node-0', SLOT_0X))
    ok('an unkeyed slot throws a TasraError', cold instanceof TasraError)
    ok('…marked retryable', isRetryable(cold))
    ok('…naming the node, the slot and the cause', /node-0 served slot 0xcdcdcdcd….*DKG has not completed/s.test(String(cold)), `message was ${String(cold)}`)

    // A 404 is a different thing: the slot is unknown, and the error carries what the node said.
    publicMode = 404
    const missing = await thrown(() => fetchMpk('http://node-0', SLOT_0X))
    ok('an unknown slot reports the status', /404/.test(String(missing)))
    ok('…and names the call with the slot prefix', /fetchMpk\(0xcdcdcdcd…\)/.test(String(missing)), `message was ${String(missing)}`)
    ok('…and is NOT retryable like the cold-DKG case', !isRetryable(missing))
    publicMode = 'serve'
  }

  // ─── fetchAndAssembleKey: the happy path and the wire shape ─────────────────
  {
    seen.length = 0
    shardMode.clear()
    const assembled = await fetchAndAssembleKey({urls: ['http://node-0'], jwt: 'the.jwt.token'}, SLOT_0X)
    eq('the assembled key is the slot master secret', hex(assembled), hex(scalarToLe(msk)))
    const call = seen[0]!
    eq('the shard request is a POST', call.method, 'POST')
    eq('…to /v1/shards/key', call.url, 'http://node-0/v1/shards/key')
    eq('…bearing the JWT', call.headers.Authorization, 'Bearer the.jwt.token')
    eq('…with the slot id in the body, 0x-prefixed', JSON.parse(call.body), {key_slot_id: SLOT_0X})

    // A bare slot id is normalised here too — the body must carry the same form either way.
    seen.length = 0
    await fetchAndAssembleKey({urls: ['http://node-0'], jwt: 'j'}, SLOT_BARE)
    eq('a bare slot id is normalised in the request body', JSON.parse(seen[0]!.body), {key_slot_id: SLOT_0X})
    // A trailing slash is normalised.
    seen.length = 0
    await fetchAndAssembleKey({urls: ['http://node-0/'], jwt: 'j'}, SLOT_0X)
    eq('a trailing slash on the node url is normalised', seen[0]!.url, 'http://node-0/v1/shards/key')
  }
  {
    // Assembles from whichever k respond: every URL is asked CONCURRENTLY, and nodes that fail
    // are simply not counted. With a 1-of-1 slot one responder is enough.
    seen.length = 0
    shardMode.set(1, 500)
    shardMode.set(2, 'network')
    const assembled = await fetchAndAssembleKey(
      {urls: ['http://node-0', 'http://node-1', 'http://node-2'], jwt: 'j'},
      SLOT_0X,
    )
    eq('a partial fleet still assembles', hex(assembled), hex(scalarToLe(msk)))
    eq('every node was asked, not just the first', seen.filter(s => s.url.includes('/shards/key')).length, 3)
    shardMode.clear()
  }

  // ─── the failure classification ─────────────────────────────────────────────
  {
    // ⚠ EVERY node denying the JWT is NOT retryable: the same token cannot start working, and a
    // transient-looking error gets retry-looped by a caller — a denied user hammering the fleet.
    shardMode.set(0, 401)
    shardMode.set(1, 403)
    const denied = await thrown(() => fetchAndAssembleKey({urls: ['http://node-0', 'http://node-1'], jwt: 'j'}, SLOT_0X))
    ok('an all-denied fleet throws ThresholdNotMetError', denied instanceof ThresholdNotMetError)
    ok('…marked NOT retryable', !isRetryable(denied))
    ok('…telling the caller to re-claim', /every node denied the JWT \(re-claim; retrying the same token will fail\)/.test(String(denied)))
    eq('…reporting 0 of 1 needed', [(denied as ThresholdNotMetError).got, (denied as ThresholdNotMetError).need], [0, 1])
    // The per-node reasons ride along rather than being discarded.
    eq('…carrying one reason per node', (denied as ThresholdNotMetError).reasons.length, 2)
    ok('…each naming its status', (denied as ThresholdNotMetError).reasons.some(r => r.includes('401')) && (denied as ThresholdNotMetError).reasons.some(r => r.includes('403')))

    // ⚠ A MIXED failure IS retryable — the non-auth half might clear on its own, so refusing to
    // retry would strand a caller whose fleet is merely half down.
    shardMode.set(1, 'network')
    const mixed = await thrown(() => fetchAndAssembleKey({urls: ['http://node-0', 'http://node-1'], jwt: 'j'}, SLOT_0X))
    ok('a mixed auth/network failure is retryable', isRetryable(mixed))
    ok('…and does NOT tell the caller to re-claim', !/re-claim/.test(String(mixed)))
    ok('…naming the node count', /no shards collected from 2 node\(s\)/.test(String(mixed)))

    // All non-auth is transient too.
    shardMode.set(0, 500)
    shardMode.set(1, 'network')
    const transient = await thrown(() => fetchAndAssembleKey({urls: ['http://node-0', 'http://node-1'], jwt: 'j'}, SLOT_0X))
    ok('an all-transient failure is retryable', isRetryable(transient))
    ok('…and carries both reasons', (transient as ThresholdNotMetError).reasons.length === 2)
    ok('…including the network one', (transient as ThresholdNotMetError).reasons.some(r => r.includes('ECONNREFUSED')))

    // A rejection that is not an Error at all must still produce a readable reason rather than
    // "undefined" — the reasons are the only diagnosis the caller gets.
    shardMode.clear()
    shardMode.set(0, 'non-error')
    const odd = await thrown(() => fetchAndAssembleKey({urls: ['http://node-0'], jwt: 'j'}, SLOT_0X))
    ok('a non-Error rejection still yields a readable reason', /node-0 hung up/.test(String(odd)))
    shardMode.clear()

    // No URLs at all: nothing to ask, so `need` is 0 rather than 1 — claiming one was needed
    // would misreport a caller's own configuration mistake as a fleet failure.
    const none = await thrown(() => fetchAndAssembleKey({urls: [], jwt: 'j'}, SLOT_0X))
    ok('an empty node list throws ThresholdNotMetError', none instanceof ThresholdNotMetError)
    eq('…with need 0, not 1', (none as ThresholdNotMetError).need, 0)
    eq('…and no reasons', (none as ThresholdNotMetError).reasons.length, 0)
    ok('…naming zero nodes', /no shards collected from 0 node\(s\)/.test(String(none)))
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ keys.node-client: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ keys.node-client: ${passed} checks passed`)
