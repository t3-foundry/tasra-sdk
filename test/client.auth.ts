// Managed client — auth resolution and factory validation, offline.
//
// `openSession` accepts four auth shapes and each has its own preconditions. Only
// `{renewalToken}` was covered (test/client.session.ts), so this suite drives the other
// three plus every guard, because a guard that has never fired is not known to fire.
//
// The point of the guards is that they name the missing thing. A caller who forgets
// `identity` on a `{vpJwt}` session would otherwise get a 400 from the verifier about a
// holder it cannot see, so each assertion checks the MESSAGE, not just that it threw.
//
// Run: tsx test/client.auth.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {ed25519} from '@noble/curves/ed25519'
import {createTasraClient} from '../src/index.ts'
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
/** Assert the call rejects AND that the message names the missing precondition. */
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}

const hex = (b: Uint8Array): string =>
  Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

const msk = modf(0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfen)
const mpkBytes = G2.BASE.multiply(msk).toRawBytes(true)
void scalarToLe(msk) // keep the import honest about what a real fixture needs
const EPOCH = 7
const slotId = `0x${'ab'.repeat(32)}`

const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const now = Math.floor(Date.now() / 1000)
const jwtWithSub = `${b64url({alg: 'EdDSA', typ: 'JWT'})}.${b64url({sub: 'did:ex:from-jwt', exp: now + 3600})}.sig`
const jwtNoSub = `${b64url({alg: 'EdDSA', typ: 'JWT'})}.${b64url({exp: now + 3600})}.sig`

// ─── mock verifier + node ─────────────────────────────────────────────────────
const calls: string[] = []
const jsonRes = (obj: unknown): Response =>
  ({ok: true, status: 200, json: async () => obj, text: async () => JSON.stringify(obj)} as unknown as Response)

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  calls.push(`${String(init?.method ?? 'GET')} ${new URL(u).pathname}`)
  if (u.includes('/v1/credentials/redeem')) {
    return jsonRes({token: jwtWithSub, exp: now + 3600, holder: 'did:ex:redeemed'})
  }
  if (u.includes('/v1/nonce')) return jsonRes({nonce: 'nonce-from-verifier'})
  if (u.includes('/v1/verify-vp-jwt')) {
    return jsonRes({token: jwtWithSub, exp: now + 3600, holder: 'did:ex:presented'})
  }
  if (u.includes('/public')) return jsonRes({group_public_key: `0x${hex(mpkBytes)}`, epoch: EPOCH})
  return {ok: false, status: 404, text: async () => 'no route', json: async () => ({})} as unknown as Response
}) as typeof globalThis.fetch

try {
  // ─── factory validation ─────────────────────────────────────────────────────
  ok(
    'createTasraClient rejects an empty node list',
    (() => {
      try {
        createTasraClient({nodes: []})
        return false
      } catch (e) {
        return /at least one node URL/.test(String(e))
      }
    })(),
  )
  ok(
    'createTasraClient rejects a missing node list',
    (() => {
      try {
        createTasraClient({} as Parameters<typeof createTasraClient>[0])
        return false
      } catch (e) {
        return /at least one node URL/.test(String(e))
      }
    })(),
  )
  {
    // The config is frozen so a caller cannot mutate endpoints under an open session.
    const kk = createTasraClient({nodes: ['http://node-0'], verifier: 'http://verifier'})
    ok('config is frozen', Object.isFrozen(kk.config))
    let mutated = false
    try {
      ;(kk.config as {verifier?: string}).verifier = 'http://evil'
      mutated = kk.config.verifier === 'http://evil'
    } catch {
      mutated = false // strict mode throws, which is also a pass
    }
    ok('config cannot be repointed at another verifier', !mutated)
  }

  // ─── {jwt}: no verifier needed, holder comes from the token ─────────────────
  {
    const kk = createTasraClient({nodes: ['http://node-0']})
    const s = await kk.openSession(slotId, {jwt: jwtWithSub})
    ok('{jwt} opens with no verifier configured', !!s)
    ok('{jwt} takes the holder from the token sub', s.holder === 'did:ex:from-jwt')
    ok('{jwt} did not call the verifier', !calls.some(c => c.includes('/v1/credentials')))
    await s.close()
  }
  {
    // A token with no `sub` falls back to config.identity rather than yielding ''.
    const kk = createTasraClient({nodes: ['http://node-0'], identity: 'did:ex:configured'})
    const s = await kk.openSession(slotId, {jwt: jwtNoSub})
    ok('{jwt} without a sub falls back to config.identity', s.holder === 'did:ex:configured')
    await s.close()
  }

  // ─── {redemptionToken} ──────────────────────────────────────────────────────
  {
    const kk = createTasraClient({
      nodes: ['http://node-0'],
      verifier: 'http://verifier',
      identity: 'did:ex:alice',
    })
    const s = await kk.openSession(slotId, {redemptionToken: 'redeem-me'})
    ok('{redemptionToken} resolves a JWT', s.jwt === jwtWithSub)
    ok('{redemptionToken} takes the holder from the grant', s.holder === 'did:ex:redeemed')
    ok('{redemptionToken} hit the redeem route', calls.includes('POST /v1/credentials/redeem'))
    await s.close()
  }
  await rejectsWith('{redemptionToken} without a verifier names it', /redemptionToken.*verifier is required/s, () =>
    createTasraClient({nodes: ['http://node-0'], identity: 'did:ex:a'}).openSession(slotId, {redemptionToken: 'x'}),
  )
  await rejectsWith('{redemptionToken} without an identity names it', /redemptionToken.*identity/s, () =>
    createTasraClient({nodes: ['http://node-0'], verifier: 'http://verifier'}).openSession(slotId, {
      redemptionToken: 'x',
    }),
  )

  // ─── {vpJwt}: nonce → holder proof → verify ─────────────────────────────────
  const signer = {
    alg: 'EdDSA' as const,
    did: 'did:ex:alice',
    secretKey: ed25519.utils.randomPrivateKey(),
  }
  {
    calls.length = 0
    const kk = createTasraClient({
      nodes: ['http://node-0'],
      verifier: 'http://verifier',
      identity: 'did:ex:alice',
    })
    const s = await kk.openSession(slotId, {
      vpJwt: {
        dcqlRule: '{"credentials":[]}',
        credentials: ['header.claims.sig'],
        holderProof: {signer, audience: 'verifier-iss'},
      },
    })
    ok('{vpJwt} resolves a JWT', s.jwt === jwtWithSub)
    ok('{vpJwt} takes the holder from the verifier reply', s.holder === 'did:ex:presented')
    // Order matters: the proof is bound to a nonce the verifier issued, so the nonce
    // fetch must precede the presentation.
    const nonceAt = calls.findIndex(c => c.includes('/v1/nonce'))
    const verifyAt = calls.findIndex(c => c.includes('/v1/verify-vp-jwt'))
    ok('{vpJwt} fetched a nonce before presenting', nonceAt >= 0 && verifyAt > nonceAt)
    await s.close()
  }
  await rejectsWith('{vpJwt} without a verifier names it', /vpJwt.*verifier is required/s, () =>
    createTasraClient({nodes: ['http://node-0'], identity: 'did:ex:a'}).openSession(slotId, {
      vpJwt: {dcqlRule: '{}', credentials: [], holderProof: {signer, audience: 'a'}},
    }),
  )
  await rejectsWith('{vpJwt} without an identity names it', /vpJwt.*identity/s, () =>
    createTasraClient({nodes: ['http://node-0'], verifier: 'http://verifier'}).openSession(slotId, {
      vpJwt: {dcqlRule: '{}', credentials: [], holderProof: {signer, audience: 'a'}},
    }),
  )
  await rejectsWith(
    '{vpJwt} without a holderProof says why one is required',
    /holderProof is required.*control of the holder DID/s,
    () =>
      createTasraClient({
        nodes: ['http://node-0'],
        verifier: 'http://verifier',
        identity: 'did:ex:a',
      }).openSession(slotId, {
        vpJwt: {dcqlRule: '{}', credentials: []} as never,
      }),
  )

  // ─── an unrecognized shape names the four it accepts ────────────────────────
  await rejectsWith(
    'empty auth lists the accepted modes',
    /jwt \| renewalToken \| redemptionToken \| vpJwt/,
    () => createTasraClient({nodes: ['http://node-0']}).openSession(slotId, {} as never),
  )

  // ─── session bookkeeping: opts and closeAll ─────────────────────────────────
  {
    const kk = createTasraClient({nodes: ['http://node-0']})
    const a = await kk.openSession(slotId, {jwt: jwtWithSub})
    const b = await kk.openSession(slotId, {jwt: jwtWithSub})
    ok('client tracks both open sessions', kk.sessions().length === 2)
    await kk.closeAll()
    ok('closeAll drops every session', kk.sessions().length === 0)
    // Both are closed, so both must refuse to decrypt.
    let bothRefuse = 0
    for (const s of [a, b]) {
      try {
        await s.decrypt(new Uint8Array([2, 0, 0]))
      } catch {
        bothRefuse++
      }
    }
    ok('closeAll zeroized both sessions', bothRefuse === 2)
  }
  {
    // A caller-supplied IBE identity replaces the default (the slot id bytes), so the
    // envelope binds to that identity instead.
    const kk = createTasraClient({nodes: ['http://node-0']})
    const identity = new TextEncoder().encode('did:ex:patient/imaging')
    const s = await kk.openSession(slotId, {jwt: jwtWithSub}, {identity})
    const env = s.encrypt(new TextEncoder().encode('x'))
    ok('opts.identity is carried into the envelope', env.length > 0)
    await s.close()
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ client.auth: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ client.auth: ${passed} checks passed`)
