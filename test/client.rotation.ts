// Managed session — threshold sign paths and rotation recovery, offline.
//
// Three uncovered behaviours, each one a silent-wrong-answer risk rather than a crash:
//
//   1. `sign` / `signDigest` must refresh the JWT BEFORE calling the node, or a
//      long-lived session starts 401-ing on an operation the caller believes is
//      authorized.
//   2. `ensureFresh` picks up a rotation. A renewal often coincides with one (revoking a
//      user rotates the slot), and if the session kept a stale epoch every later
//      `encrypt` would bind to a key the fleet has retired.
//   3. `decrypt` recovers from a rotation exactly once, and when recovery does not help
//      it reports BOTH epochs. Without that the caller sees an opaque AEAD failure and
//      cannot tell a rotation from corruption.
//
// Run: tsx test/client.rotation.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {createTasraClient, encryptEnvelope, hexToBytes, toBytes, SlotRotatedError} from '../src/index.ts'
import {scalarToLe} from '../src/crypto/kem.ts'

const G2 = bls12_381.G2.ProjectivePoint
const ORDER = bls12_381.fields.Fr.ORDER
const modf = (n: bigint): bigint => ((n % ORDER) + ORDER) % ORDER

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i])
const hex = (b: Uint8Array): string =>
  Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

// ─── two generations of key material, so a rotation is observable ─────────────
// 1-of-1 in both, which makes assembleKey([{id:1, bytes}]) the identity (λ = 1).
const keyFor = (seed: bigint) => {
  const msk = modf(seed)
  return {msk, mskBytes: scalarToLe(msk), mpkBytes: G2.BASE.multiply(msk).toRawBytes(true)}
}
const gen2 = keyFor(0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfen)
const gen3 = keyFor(0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffn)

const slotId = `0x${'ef'.repeat(32)}`
const slotIdBytes = hexToBytes(slotId)

const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const now = Math.floor(Date.now() / 1000)
const mkJwt = (exp: number): string =>
  `${b64url({alg: 'EdDSA', typ: 'JWT'})}.${b64url({sub: 'did:ex:alice', exp})}.sig`
const staleJwt = mkJwt(now + 10) // inside the 30s skew ⇒ "expiring soon"
const freshJwt = mkJwt(now + 3600)

// ─── mock fleet whose epoch can be rotated mid-test ───────────────────────────
const live = {epoch: 2, key: gen2}
let redeems = 0
/** How many LEADING redeems hand back a near-expiry JWT. A long-lived session renews
 *  and is still near expiry, so >1 is what puts a stale JWT in front of a later
 *  ensureFresh — with 1, the first renewal makes it fresh and ensureFresh correctly
 *  becomes a no-op. */
let staleRedeems = 0
let lastSignAuth: string | undefined
const jsonRes = (obj: unknown): Response =>
  ({ok: true, status: 200, json: async () => obj, text: async () => JSON.stringify(obj)} as unknown as Response)

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  const auth = (init?.headers as Record<string, string> | undefined)?.Authorization

  if (u.includes('/v1/renewals/redeem')) {
    redeems++
    const token = redeems <= staleRedeems ? staleJwt : freshJwt
    return jsonRes({token, exp: now + 3600, holder: 'did:ex:alice'})
  }
  if (u.includes('/v1/sign/eoa-digest')) {
    lastSignAuth = auth
    return jsonRes({
      group_public_key: `0x${'77'.repeat(33)}`, // compressed secp256k1
      signature_r: `0x${'11'.repeat(32)}`,
      signature_s: `0x${'22'.repeat(32)}`,
      signature_v: 1,
    })
  }
  if (u.endsWith('/v1/sign')) {
    lastSignAuth = auth
    return jsonRes({
      key_slot_id: slotId,
      group_public_key: `0x${'33'.repeat(32)}`,
      signature_r: `0x${'44'.repeat(32)}`,
      signature_z: `0x${'55'.repeat(32)}`,
      message_sha256: `0x${'66'.repeat(32)}`,
      epoch: live.epoch,
    })
  }
  if (u.includes('/public')) {
    return jsonRes({group_public_key: `0x${hex(live.key.mpkBytes)}`, epoch: live.epoch})
  }
  if (u.includes('/v1/shards/key')) {
    return jsonRes({identifier: 1, shard: b64(live.key.mskBytes), epoch: live.epoch})
  }
  return {ok: false, status: 404, text: async () => 'no route', json: async () => ({})} as unknown as Response
}) as typeof globalThis.fetch

const cfg = {nodes: ['http://node-0'], verifier: 'http://verifier', identity: 'did:ex:alice'}

try {
  // ─── 1. sign refreshes the JWT before it calls the node ─────────────────────
  {
    live.epoch = 2
    live.key = gen2
    redeems = 0
    staleRedeems = 0
    const kk = createTasraClient(cfg)
    // Open with a JWT that is already near expiry, and a renewal token to fix it.
    const s = await kk.openSession(slotId, {jwt: staleJwt})
    ok('session opened on a near-expiry JWT', s.jwt === staleJwt)

    // No renewal token in this mode, so ensureFresh cannot re-mint: it must NOT
    // silently continue pretending to be fresh, and must not throw either — the node
    // is the one that rejects. This is the documented "fail loud at the node" path.
    const sig = await s.sign(new TextEncoder().encode('msg'))
    ok('sign returns the group signature', sig.signature.r.length === 32 && sig.signature.z.length === 32)
    ok('sign reports the slot', sig.keySlotId === slotId)
    ok('sign carried the session JWT as a bearer token', lastSignAuth === `Bearer ${staleJwt}`)
    ok('sign did not renew without a renewal token', redeems === 0)

    const eoa = await s.signDigest(new Uint8Array(32).fill(9))
    ok('signDigest returns r and s', eoa.r.length === 32 && eoa.s.length === 32)
    // `signature_v: 1` is the raw recovery id, so yParity is 1 — NOT 27/28. Getting
    // this wrong yields a signature that recovers to the wrong address.
    ok('signDigest maps the recovery id to yParity', eoa.yParity === 1, `yParity=${String(eoa.yParity)}`)
    await s.close()
  }

  // ─── with a renewal token, sign renews a stale JWT before calling the node ──
  {
    live.epoch = 2
    live.key = gen2
    redeems = 0
    staleRedeems = 1 // the session opens holding a near-expiry JWT
    const kk = createTasraClient(cfg)
    const s = await kk.openSession(slotId, {renewalToken: 'tok'})
    ok('open redeemed once and took the stale token', redeems === 1 && s.jwt === staleJwt)

    await s.sign(new TextEncoder().encode('msg'))
    ok('sign renewed the stale JWT first', redeems === 2 && s.jwt === freshJwt)
    ok('and sent the RENEWED token to the node', lastSignAuth === `Bearer ${freshJwt}`)

    await s.signDigest(new Uint8Array(32).fill(1))
    ok('signDigest does not re-renew an already fresh JWT', redeems === 2)
    await s.close()
  }

  // ─── 2. ensureFresh picks up a rotation that happened during a renewal ──────
  {
    live.epoch = 2
    live.key = gen2
    redeems = 0
    staleRedeems = 1
    const kk = createTasraClient(cfg)
    const s = await kk.openSession(slotId, {renewalToken: 'tok'})
    ok('session starts at the live epoch', s.epoch === 2)
    const mpkAtOpen = s.mpkBytes

    // The fleet rotates while the session is open — which is exactly what revoking a
    // user does. The stale JWT means the next ensureFresh will renew, and the renewal
    // is where the new epoch has to be noticed.
    live.epoch = 3
    live.key = gen3
    await s.ensureFresh()
    ok('ensureFresh renewed', redeems === 2)
    ok('ensureFresh adopted the new epoch', s.epoch === 3, `epoch=${String(s.epoch)}`)
    ok('ensureFresh adopted the new group key', !bytesEq(s.mpkBytes, mpkAtOpen))

    // An envelope encrypted now must bind to the NEW epoch — if the session had kept
    // the stale one, every later encrypt would target a retired key.
    const env = s.encrypt(new TextEncoder().encode('after rotation'))
    ok('encrypt after rotation binds the new epoch', bytesEq(await s.decrypt(env), new TextEncoder().encode('after rotation')))
    await s.close()
  }

  // ─── the same, but with a key already assembled: it must be re-assembled ────
  {
    live.epoch = 2
    live.key = gen2
    redeems = 0
    // TWO: the decrypt below renews once (open → stale, decrypt → stale again), so the
    // JWT is still near expiry when ensureFresh runs after the rotation. With one, the
    // decrypt's renewal would leave it fresh and ensureFresh would rightly do nothing.
    staleRedeems = 2
    const kk = createTasraClient(cfg)
    const s = await kk.openSession(slotId, {renewalToken: 'tok'})
    // Force an assemble at epoch 2 (decrypt is what assembles).
    const plain = new TextEncoder().encode('epoch 2 payload')
    ok('epoch-2 round-trip assembles the key', bytesEq(await s.decrypt(s.encrypt(plain)), plain))

    live.epoch = 3
    live.key = gen3
    await s.ensureFresh()
    ok('ensureFresh re-assembled against the new epoch', s.epoch === 3)
    // The proof that it re-assembled rather than kept the old key: a fresh envelope
    // under the NEW key decrypts without going through the rotation-recovery branch.
    const after = new TextEncoder().encode('epoch 3 payload')
    ok('the newly assembled key decrypts new material', bytesEq(await s.decrypt(s.encrypt(after)), after))
    await s.close()
  }

  // ─── 3. decrypt recovers from a rotation, once ──────────────────────────────
  {
    live.epoch = 2
    live.key = gen2
    const kk = createTasraClient(cfg)
    const s = await kk.openSession(slotId, {jwt: freshJwt})

    // Assemble the epoch-2 key by decrypting an epoch-2 envelope.
    const plain2 = new TextEncoder().encode('sealed under epoch 2')
    const env2 = s.encrypt(plain2)
    ok('epoch-2 envelope round-trips', bytesEq(await s.decrypt(env2), plain2))

    // The fleet rotates. An envelope sealed under the NEW key cannot open with the
    // epoch-2 key the session holds.
    const plain3 = new TextEncoder().encode('sealed under epoch 3')
    const env3 = toBytes(
      encryptEnvelope(slotIdBytes, gen3.mpkBytes, slotIdBytes, plain3, BigInt(3)),
    )
    live.epoch = 3
    live.key = gen3

    const out3 = await s.decrypt(env3)
    ok('decrypt re-assembled against the new epoch and recovered', bytesEq(out3, plain3))
    ok('the session adopted the new epoch', s.epoch === 3)

    // ─── and when re-assembling does NOT help, it names both epochs ───────────
    const orphan = toBytes(
      encryptEnvelope(slotIdBytes, keyFor(0xdeadbeefn).mpkBytes, slotIdBytes, plain3, BigInt(9)),
    )
    let rotated: SlotRotatedError | undefined
    try {
      await s.decrypt(orphan)
    } catch (error) {
      if (error instanceof SlotRotatedError) rotated = error
    }
    ok('an unrecoverable epoch mismatch throws SlotRotatedError', rotated !== undefined)
    ok('it reports the envelope epoch as expected', rotated?.expected === 9, `expected=${String(rotated?.expected)}`)
    ok('it reports the slot epoch as actual', rotated?.actual === 3, `actual=${String(rotated?.actual)}`)
    ok('it is marked retryable', rotated?.retryable === true)
    ok(
      'its message carries both epochs, not an opaque AEAD failure',
      /epoch 9/.test(rotated?.message ?? '') && /epoch 3/.test(rotated?.message ?? ''),
      rotated?.message,
    )
    await s.close()
  }

  // ─── a same-epoch failure is NOT reported as a rotation ─────────────────────
  {
    live.epoch = 2
    live.key = gen2
    const kk = createTasraClient(cfg)
    const s = await kk.openSession(slotId, {jwt: freshJwt})
    // Corrupt an epoch-2 envelope. The epoch matches, so the rotation branch must not
    // fire and the caller must see the underlying failure instead.
    const env = s.encrypt(new TextEncoder().encode('x'))
    const last = env.length - 1
    env[last] = (env[last] ?? 0) ^ 0xff // flip the AEAD tag
    let asRotation = false
    try {
      await s.decrypt(env)
    } catch (error) {
      asRotation = error instanceof SlotRotatedError
    }
    ok('a same-epoch AEAD failure is not disguised as a rotation', !asRotation)
    await s.close()
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ client.rotation: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ client.rotation: ${passed} checks passed`)
