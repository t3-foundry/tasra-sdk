// Managed Client + Session — offline integration test with a mocked node/verifier
// fleet. Proves openSession obtains a JWT + assembles the slot key, encrypt→decrypt
// round-trips through the assembled msk, ensureFresh() auto-renews a near-expiry
// JWT (and is a no-op when fresh), and close() zeroizes the key. No live network.
//
// Run: tsx test/client.session.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {createTasraClient, fromBytes} from '../src/index.ts'
import {scalarToLe} from '../src/crypto/kem.ts'

const G2 = bls12_381.G2.ProjectivePoint
const ORDER = bls12_381.fields.Fr.ORDER
const modf = (n: bigint): bigint => ((n % ORDER) + ORDER) % ORDER

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean): void {
  if (cond) passed++
  else failures.push(name)
}
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i])
const hex = (b: Uint8Array): string =>
  Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// ─── crypto fixture: a 1-of-1 key so encrypt→decrypt actually round-trips ──────
const msk = modf(0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfen)
const mskBytes = scalarToLe(msk) // assembleKey([{id:1, bytes:mskBytes}]) === mskBytes (λ=1)
const mpkBytes = G2.BASE.multiply(msk).toRawBytes(true) // 96-byte compressed G2
const EPOCH = 3
const slotId = '0x' + 'cd'.repeat(32) // 32-byte slot id

// ─── fake JWTs (the auth helpers only DECODE, never verify the signature) ──────
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const mkJwt = (sub: string, expSecs: number): string =>
  `${b64url({alg: 'EdDSA', typ: 'JWT'})}.${b64url({sub, exp: expSecs})}.sig`
const now = Math.floor(Date.now() / 1000)
const freshJwt = mkJwt('did:ex:alice', now + 3600) // not expiring
const staleJwt = mkJwt('did:ex:alice', now + 10) // within the 30s skew → expiring

// ─── mock node + verifier fleet ───────────────────────────────────────────────
let redeemCount = 0
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
const jsonRes = (obj: unknown): Response =>
  ({ok: true, status: 200, json: async () => obj, text: async () => JSON.stringify(obj)} as unknown as Response)

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string) => {
  const u = String(url)
  if (u.includes('/v1/renewals/redeem')) {
    redeemCount++
    // 1st redeem (at open) → stale; subsequent (ensureFresh) → fresh.
    const token = redeemCount === 1 ? staleJwt : freshJwt
    return jsonRes({token, exp: now + 3600, holder: 'did:ex:alice'})
  }
  if (u.includes('/v1/keys/') && u.includes('/public')) {
    return jsonRes({group_public_key: '0x' + hex(mpkBytes), epoch: EPOCH})
  }
  if (u.includes('/v1/shards/key')) {
    return jsonRes({identifier: 1, shard: b64(mskBytes), epoch: EPOCH})
  }
  return {ok: false, status: 404, text: async () => 'no route', json: async () => ({})} as unknown as Response
}) as typeof globalThis.fetch

const plaintext = new TextEncoder().encode('hello from a managed session 🔐')

try {
  const kk = createTasraClient({
    nodes: ['http://node-0'],
    verifier: 'http://verifier',
    identity: 'did:ex:alice',
  })

  // open — renewalToken auth resolves a JWT (the 1st, stale one) then assembles.
  const s = await kk.openSession(slotId, {renewalToken: 'renew-tok-1'})
  ok('openSession returns a session', !!s)
  ok('holder comes from the renewal grant', s.holder === 'did:ex:alice')
  ok('mpk is a 96-byte compressed G2', s.mpkBytes.length === 96)
  ok('epoch matches the node', s.epoch === EPOCH)
  ok('redeemRenewalToken called once on open', redeemCount === 1)
  ok('session holds the open-time (stale) JWT', s.jwt === staleJwt)
  ok('client tracks one open session', kk.sessions().length === 1)

  // encrypt — local, no I/O, no renewal; v0x02 stamped with the session epoch.
  const env = s.encrypt(plaintext)
  ok('envelope is v0x02', env[0] === 0x02)
  ok('envelope carries the session epoch', fromBytes(env).epoch === BigInt(EPOCH))
  ok('encrypt did not renew', redeemCount === 1)

  // ensureFresh — the stale JWT is near expiry → renews to the fresh one.
  await s.ensureFresh()
  ok('ensureFresh renewed the JWT', redeemCount === 2 && s.jwt === freshJwt)
  // ensureFresh again — fresh JWT → zero I/O.
  await s.ensureFresh()
  ok('ensureFresh is a no-op when fresh', redeemCount === 2)

  // decrypt — round-trips through the assembled master key.
  const out = await s.decrypt(env)
  ok('decrypt round-trips the plaintext', bytesEq(out, plaintext))
  ok('decrypt did not renew (JWT already fresh)', redeemCount === 2)

  // close — zeroizes the key and drops from the client.
  await s.close()
  ok('client has no open sessions after close', kk.sessions().length === 0)
  let threw = false
  try {
    await s.decrypt(env)
  } catch {
    threw = true
  }
  ok('decrypt rejects after close (key zeroized)', threw)

  // a node-only client (no verifier) rejects renewal auth with a clear error.
  let openThrew = false
  try {
    const bare = createTasraClient({nodes: ['http://node-0']})
    await bare.openSession(slotId, {renewalToken: 'x'})
  } catch (e) {
    openThrew = /verifier is required/.test(String(e))
  }
  ok('openSession({renewalToken}) without a verifier throws clearly', openThrew)
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ client.session: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ client.session: ${passed} checks passed`)
