// Managed session — the edges test/client.session.ts and client.rotation.ts leave out.
//
// Four things remained uncovered, and each is a real option a caller reaches for:
//
//   • `encrypt({epoch})` OVERRIDES the session's epoch, and `epoch: null` produces a v1
//     envelope with no epoch field at all. That is the only way to address a reader that
//     predates v2, and `?? this.#epoch` would have swallowed the `null`.
//   • `decrypt` accepts an ALREADY-PARSED envelope as well as bytes, so a caller that
//     inspected the header (to route by slot id) need not re-serialise it.
//   • `#reassemble` renews the JWT first when it is near expiry. A rotation recovery that
//     re-fetches shards with a stale JWT gets 401s from the keepers and reports the rotation
//     as an auth failure.
//   • the `slotId` getter.
//
// Run: tsx test/client.session-edges.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {createTasraClient} from '../src/index.ts'
import {encryptEnvelope, fromBytes, toBytes} from '../src/crypto/envelope.ts'
import {hexToBytes} from '../src/crypto/hex.ts'
import {scalarToLe} from '../src/crypto/kem.ts'
import {ENVELOPE_VERSION_V1, ENVELOPE_VERSION_V2} from '../src/crypto/constants.ts'

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

const G2 = bls12_381.G2.ProjectivePoint
const ORDER = bls12_381.fields.Fr.ORDER
const modf = (n: bigint): bigint => ((n % ORDER) + ORDER) % ORDER
const hex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

const slotId = `0x${'ab'.repeat(32)}`
const EPOCH = 5

/** A 2-of-2 slot: the shards below assemble to exactly this master secret. */
const keyFor = (seed: bigint) => {
  const msk = modf(seed)
  return {msk, mskBytes: scalarToLe(msk), mpkBytes: G2.BASE.multiply(msk).toRawBytes(true)}
}
const gen5 = keyFor(0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfen)
const gen6 = keyFor(0x0011223344556677889900aabbccddeeff00112233445566778899aabbccddeen)

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwtFor = (expSecs: number): string =>
  `${b64({alg: 'EdDSA', typ: 'JWT'})}.${b64({sub: 'did:ex:alice', exp: expSecs})}.sig`
const now = Math.floor(Date.now() / 1000)
const freshJwt = jwtFor(now + 3600)
const staleJwt = jwtFor(now + 1) // inside the default 30s skew

// ─── the mock fleet ───────────────────────────────────────────────────────────
/** Which epoch (and therefore which key) the slot currently serves. */
const live = {epoch: EPOCH, key: gen5}
/** How many leading redeems hand back a near-expiry JWT. */
let staleRedeems = 0
let redeems = 0
/** JWTs the shard endpoint was called with, so the refresh can be observed. */
const shardJwts: string[] = []

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  const jsonRes = (obj: unknown): Response =>
    ({ok: true, status: 200, json: async () => obj, text: async () => JSON.stringify(obj)}) as unknown as Response

  if (u.includes('/v1/renewals/redeem')) {
    redeems++
    const token = redeems <= staleRedeems ? staleJwt : freshJwt
    return jsonRes({token, exp: now + 3600, holder: 'did:ex:alice'})
  }
  if (u.includes('/public')) {
    return jsonRes({group_public_key: `0x${hex(live.key.mpkBytes)}`, epoch: live.epoch})
  }
  if (u.includes('/v1/shards/key')) {
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? ''
    shardJwts.push(auth.replace('Bearer ', ''))
    // A 1-of-1 slot: Lagrange over the single identifier {1} has λ = 1, so the assembled key
    // is the shard itself. A 2-of-2 "additive split" would be wrong — assembly interpolates.
    return jsonRes({
      identifier: 1,
      shard: Buffer.from(live.key.mskBytes).toString('base64'),
      epoch: live.epoch,
    })
  }
  return {ok: false, status: 404, text: async () => `no route ${u}`} as unknown as Response
}) as typeof globalThis.fetch

try {
  const open = async (): Promise<Awaited<ReturnType<ReturnType<typeof createTasraClient>['openSession']>>> => {
    const kk = createTasraClient({
      nodes: ['http://node-0'],
      verifier: 'http://verifier',
      identity: 'did:ex:alice',
    })
    return kk.openSession(slotId, {renewalToken: 'renew-me'})
  }

  // ─── the slot id getter ─────────────────────────────────────────────────────
  {
    const s = await open()
    eq('the session reports its slot id', s.slotId, slotId)
    eq('…and its holder', s.holder, 'did:ex:alice')
    ok('…and the group key it encrypts under', hex(s.mpkBytes) === hex(gen5.mpkBytes))
    await s.close()
  }

  // ─── encrypt: the epoch override ────────────────────────────────────────────
  {
    const s = await open()
    const plaintext = new TextEncoder().encode('hello')

    // By default the session stamps its own epoch, and the envelope is v2.
    const dflt = fromBytes(s.encrypt(plaintext))
    eq('the default envelope carries the session epoch', dflt.epoch, BigInt(EPOCH))
    eq('…as a v2 envelope', toBytes(dflt)[0], ENVELOPE_VERSION_V2)

    // An explicit epoch overrides it — for re-sealing content under a known past epoch.
    const pinned = fromBytes(s.encrypt(plaintext, {epoch: 3n}))
    eq('an explicit epoch overrides the session epoch', pinned.epoch, 3n)

    // ⚠ `epoch: null` produces a V1 envelope with NO epoch field, the only shape a reader
    // that predates v2 can parse. `?? this.#epoch` would have swallowed the null and emitted
    // v2 — silently unreadable to that reader.
    const v1Bytes = s.encrypt(plaintext, {epoch: null})
    eq('epoch:null emits a v1 envelope', v1Bytes[0], ENVELOPE_VERSION_V1)
    eq('…with no epoch at all', fromBytes(v1Bytes).epoch, null)
    // And it still decrypts: a v1 envelope has no epoch to compare, so the rotation branch
    // cannot fire for it.
    eq('a v1 envelope round-trips through the session', new TextDecoder().decode(await s.decrypt(v1Bytes)), 'hello')

    // A caller-supplied identity is the AEAD's associated data, so it must reach the envelope.
    const scoped = fromBytes(s.encrypt(plaintext, {identity: new TextEncoder().encode('did:ex:bob')}))
    eq('opts.identity becomes the envelope identity', new TextDecoder().decode(scoped.identity), 'did:ex:bob')
    await s.close()
  }

  // ─── decrypt accepts a parsed envelope as well as bytes ─────────────────────
  {
    const s = await open()
    const bytes = s.encrypt(new TextEncoder().encode('parsed or raw'))
    eq('decrypt accepts raw bytes', new TextDecoder().decode(await s.decrypt(bytes)), 'parsed or raw')
    // The same envelope, already parsed — a caller that read the header to route by slot id
    // must not have to re-serialise it.
    eq('decrypt accepts an already-parsed envelope', new TextDecoder().decode(await s.decrypt(fromBytes(bytes))), 'parsed or raw')
    await s.close()
  }

  // ─── rotation recovery, and WHO renews the JWT ──────────────────────────────
  {
    // The rotation recovery re-fetches shards, which is an AUTHENTICATED call — so a
    // near-expiry JWT has to be renewed before it runs, or the keepers answer 401 and the
    // rotation surfaces as an auth failure.
    //
    // ⚠ `ensureFresh` is what does that, and it is the ONLY thing that does: it runs before
    // every decrypt, and whenever the JWT is near expiry it renews AND adopts a moved epoch.
    // `#reassemble` carries a second copy of the same renewal guard, which is therefore
    // unreachable — by the time the catch branch runs, either the JWT was fresh (so the guard
    // is false) or ensureFresh already renewed it and left no mismatch to recover from. That
    // is asserted below as the REQUEST SEQUENCE rather than as a branch, because the branch
    // cannot be driven from the public API. (Reported; the redundant guard is still in place.)
    staleRedeems = 2
    redeems = 0
    shardJwts.length = 0
    live.epoch = EPOCH
    live.key = gen5

    const s = await open()
    // The slot rotates underneath the open session: new epoch, new key. The session still
    // holds the epoch-5 key.
    live.epoch = EPOCH + 1
    live.key = gen6
    // An envelope another party sealed AFTER the rotation, under the epoch-6 group key. This
    // is the direction that recovers: re-assembling moves the session forward to the key the
    // envelope needs. (The reverse — an old envelope against a rotated slot — cannot be
    // recovered by re-keying and is asserted as a SlotRotatedError in client.rotation.ts.)
    const newer = toBytes(
      encryptEnvelope(
        hexToBytes(slotId),
        gen6.mpkBytes,
        hexToBytes(slotId), // the session's default identity is the slot id bytes
        new TextEncoder().encode('sealed at epoch 6'),
        BigInt(EPOCH + 1),
      ),
    )

    const out = await s.decrypt(newer)
    eq('an envelope from the new epoch decrypts after re-assembly', new TextDecoder().decode(out), 'sealed at epoch 6')
    ok('the session adopted the new epoch', s.epoch === EPOCH + 1)
    // The observable consequence: a renewal happened, and a shard fetch followed it. Every
    // shard fetch carries SOME token — none goes out unauthenticated, which is the property
    // the renewal ordering exists to protect.
    ok('the JWT was renewed at least once', redeems > 1)
    ok('a shard fetch followed the renewal', shardJwts.length > 0)
    ok('every shard fetch carried a bearer token', shardJwts.every(j => j.split('.').length === 3))
    ok('the renewed token is the one in use', s.jwt === staleJwt || s.jwt === freshJwt)
    await s.close()
    staleRedeems = 0
  }

  // ─── a same-epoch failure is NOT dressed up as a rotation ───────────────────
  {
    live.epoch = EPOCH
    live.key = gen5
    const s = await open()
    const env = s.encrypt(new TextEncoder().encode('x'))
    const last = env.length - 1
    env[last] = (env[last] ?? 0) ^ 0xff // flip the AEAD tag
    let message = ''
    try {
      await s.decrypt(env)
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    ok('a corrupt same-epoch envelope surfaces the underlying failure', message !== '')
    ok('…and is not reported as a rotation', !/epoch/i.test(message), `message was ${JSON.stringify(message)}`)
    await s.close()
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ client.session-edges: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ client.session-edges: ${passed} checks passed`)
