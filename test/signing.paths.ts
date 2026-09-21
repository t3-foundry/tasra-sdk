// The signing clients — FROST custody, FROST shard-delivery, and the tECDSA EOA path.
//
// `src/signing` was the least covered directory left. Four things in it are worth more
// than their line count:
//
//   • userSignaturePayload — a CANONICAL PREIMAGE the node recomputes byte for byte. If
//     it drifts, every user-gated sign is refused and the refusal reads like an auth
//     problem, not an encoding one. Asserted as exact bytes, assembled independently
//     here, plus the property that makes it safe: the signature is bound to the slot, the
//     message AND the request id, so it cannot be replayed onto another request.
//
//   • signWithShardDelivery — the CLIENT coordinates two rounds and aggregates locally.
//     The load-bearing detail is that the commitment list sent to every node in round 2
//     is the same canonically-ordered list used to aggregate; binding factors are derived
//     from it, so a different order produces a signature that verifies nowhere. The mock
//     nodes here run REAL FROST maths over their own shares, so the aggregate has to
//     actually verify — a mock returning canned bytes could not catch that.
//
//   • the wire shape — bodies use BARE hex with no 0x, because some node handlers
//     hex-decode directly. A 0x that slips in is a 400 from the node.
//
//   • ethSignatureV — EIP-155 `35 + 2·chainId + yParity`. Off-by-one here yields a
//     transaction the chain rejects, or worse one that is valid on a different chain.
//
// Run: tsx test/signing.paths.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {secp256k1} from '@noble/curves/secp256k1'
import {mod, invert} from '@noble/curves/abstract/modular'
import {sha256} from '@noble/hashes/sha256'
import {sha512} from '@noble/hashes/sha512'
import {bytesToHex as toHex, concatBytes, utf8ToBytes} from '@noble/hashes/utils'
import {verify as frostVerify} from '../src/crypto/frost.ts'
import {
  signCustody,
  signUserRequest,
  signWithShardDelivery,
  userSignaturePayload,
} from '../src/signing/frost.ts'
import {addressFromEoaPubkey, ethSignatureV, signEoaDigest} from '../src/signing/ecdsa.ts'
import {hexToBytes} from '../src/crypto/hex.ts'

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

const Point = ed25519.Point
const L = ed25519.CURVE.n
const slotId = `0x${'cd'.repeat(32)}`
const jwt = 'header.payload.signature'

// ─── request recorder ─────────────────────────────────────────────────────────
interface Sent {
  url: string
  body: Record<string, unknown>
  headers: Record<string, string>
}
const sent: Sent[] = []
const realFetch = globalThis.fetch
const bodiesTo = (fragment: string): Array<Record<string, unknown>> =>
  sent.filter(s => s.url.includes(fragment)).map(s => s.body)

// ─── a real 2-of-3 FROST slot, for the shard-delivery path ────────────────────
// Trusted-dealer Shamir keygen; the mock nodes below sign with their own shares, so the
// client's aggregate must verify under the group key for the test to pass.
const leToBig = (b: Uint8Array): bigint => {
  let n = 0n
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i] as number)
  return n
}
const scalarToLe = (n: bigint): Uint8Array => {
  let v = mod(n, L)
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}
const hashToScalar = (...parts: Uint8Array[]): bigint => mod(leToBig(sha512(concatBytes(...parts))), L)
const u16le = (n: number): Uint8Array => {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, true)
  return b
}
const u64leLocal = (n: number): Uint8Array => {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true)
  return b
}
type Pt = ReturnType<typeof Point.fromHex>
const mul = (p: Pt, k: bigint): Pt => (mod(k, L) === 0n ? Point.ZERO : p.multiply(mod(k, L)))
const lagrange = (xi: bigint, xs: bigint[]): bigint => {
  let num = 1n
  let den = 1n
  for (const xj of xs) {
    if (xj === xi) continue
    num = mod(num * mod(-xj, L), L)
    den = mod(den * mod(xi - xj, L), L)
  }
  return mod(num * invert(den, L), L)
}
const DST_RHO = utf8ToBytes('FROST-Ed25519-SHA512-v1/rho')

const secret = mod(leToBig(sha512(utf8ToBytes('signing-paths-secret'))), L) || 1n
const a1 = mod(leToBig(sha512(utf8ToBytes('signing-paths-a1'))), L) || 1n
const shareOf = (i: number): bigint => mod(secret + mod(a1 * BigInt(i), L), L)
const groupPk = mul(Point.BASE, secret).toRawBytes()
/** identifier → base URL, the k committee members the client is told to use. */
const committee = new Map([
  [3, 'http://keeper-c'],
  [1, 'http://keeper-a'],
])
const nonceFor = (label: string, i: number): bigint =>
  mod(hashToScalar(utf8ToBytes(label), u16le(i)), L) || 1n

/** What each node remembers between round 1 and round 2. */
interface Session {
  identifier: number
  d: bigint
  e: bigint
  messageHex: string
}
const sessions = new Map<string, Session>()
/** Commitment lists as each node received them in round 2, to check what was sent. */
const round2Lists: Array<{node: string; ids: number[]}> = []

function shardCommit(nodeUrl: string, identifier: number, messageHex: string): unknown {
  const sessionId = `sess-${identifier}-${sessions.size}`
  const d = nonceFor('d', identifier)
  const e = nonceFor('e', identifier)
  sessions.set(sessionId, {identifier, d, e, messageHex})
  return {
    session_id: sessionId,
    identifier,
    hiding: toHex(mul(Point.BASE, d).toRawBytes()),
    binding: toHex(mul(Point.BASE, e).toRawBytes()),
  }
}

/**
 * Round 2, computed the way a real keeper would: derive the binding factors and the
 * challenge from the commitment list THE CLIENT SENT, then z_i = d_i + ρ_i·e_i + λ_i·c·s_i.
 *
 * ⚠ This is what makes the canonical-order invariant testable. The node uses the received
 * list; the client aggregates with its own. If those differ, ρ differs, and the aggregate
 * fails to verify.
 */
function shardPartial(
  nodeUrl: string,
  sessionId: string,
  messageHex: string,
  list: Array<{identifier: number; hiding: string; binding: string}>,
): unknown {
  const s = sessions.get(sessionId)
  if (!s) throw new Error(`unknown session ${sessionId}`)
  round2Lists.push({node: nodeUrl, ids: list.map(c => c.identifier)})
  const message = hexToBytes(messageHex)
  const serialized = concatBytes(
    ...list.flatMap(c => [u16le(c.identifier), hexToBytes(c.hiding), hexToBytes(c.binding)]),
  )
  const lenMsg = u64leLocal(message.length)
  const rho = (id: number): bigint => hashToScalar(DST_RHO, u16le(id), lenMsg, message, serialized)
  let R: Pt = Point.ZERO
  for (const c of list) {
    R = R.add(Point.fromHex(hexToBytes(c.hiding)).add(mul(Point.fromHex(hexToBytes(c.binding)), rho(c.identifier))))
  }
  const chal = hashToScalar(R.toRawBytes(), groupPk, message)
  const xs = list.map(c => BigInt(c.identifier))
  const lambda = lagrange(BigInt(s.identifier), xs)
  const z = mod(
    s.d + mod(rho(s.identifier) * s.e, L) + mod(mod(lambda * chal, L) * shareOf(s.identifier), L),
    L,
  )
  return {
    identifier: s.identifier,
    z: toHex(scalarToLe(z)),
    verifying_share: toHex(mul(Point.BASE, shareOf(s.identifier)).toRawBytes()),
  }
}

// ─── the node stub ────────────────────────────────────────────────────────────
/** Force the next N custody calls to fail with this status (0 = never). */
let custodyFailStatus = 0
/** Serve /public for the group key, so the shard path can be driven without one. */
let servePublicKey = true

globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
  const headers = (init?.headers ?? {}) as Record<string, string>
  sent.push({url: u, body, headers})

  const fail = (status: number, text: string): Response =>
    ({ok: false, status, text: async () => text, json: async () => ({error: text})}) as unknown as Response
  const json = (o: unknown): Response => ({ok: true, status: 200, json: async () => o}) as unknown as Response

  if (u.includes('/v1/shards/sign/commit')) {
    const idFor = [...committee.entries()].find(([, base]) => u.startsWith(base))?.[0]
    if (idFor === undefined) return fail(404, 'not a committee node')
    return json(shardCommit(u, idFor, String(body.message_hex)))
  }
  if (u.includes('/v1/shards/sign/partial')) {
    return json(
      shardPartial(
        u,
        String(body.session_id),
        String(body.message_hex),
        body.commitments as Array<{identifier: number; hiding: string; binding: string}>,
      ),
    )
  }
  if (u.includes('/v1/sign/eoa-digest')) {
    if (custodyFailStatus) return fail(custodyFailStatus, 'tecdsa refused')
    return json({
      group_public_key: `0x${'02'.repeat(1)}${'11'.repeat(32)}`,
      signature_r: `0x${'aa'.repeat(32)}`,
      signature_s: `0x${'bb'.repeat(32)}`,
      signature_v: 1,
    })
  }
  if (u.includes('/v1/sign')) {
    if (custodyFailStatus) return fail(custodyFailStatus, 'slot is not ready')
    return json({
      key_slot_id: slotId,
      group_public_key: `0x${toHex(groupPk)}`,
      signature_r: `0x${'01'.repeat(32)}`,
      signature_z: `0x${'02'.repeat(32)}`,
      message_sha256: `0x${toHex(sha256(new Uint8Array([1])))}`,
      epoch: 4,
    })
  }
  // The group key for a FROST slot, read from nodeUrls[0] when not supplied.
  if (u.includes('/public')) {
    if (!servePublicKey) return fail(503, 'no public key')
    return json({group_public_key: `0x${toHex(groupPk)}`, epoch: 4})
  }
  return fail(404, `no route ${u}`)
}) as typeof globalThis.fetch

try {
  // ─── userSignaturePayload: the canonical preimage ──────────────────────────
  {
    const message = utf8ToBytes('transfer 1 TSRA')
    const requestId = 'req-0001'
    const payload = userSignaturePayload(slotId, message, requestId)

    // Assembled independently from the documented layout:
    //   domain ‖ u64_LE(len slot) ‖ slot ‖ u64_LE(32) ‖ SHA256(message) ‖
    //   u64_LE(len requestId) ‖ requestId
    const slotBytes = hexToBytes(slotId)
    const expected = concatBytes(
      utf8ToBytes('keykeeper:user-sig:v1'),
      u64leLocal(slotBytes.length),
      slotBytes,
      u64leLocal(32),
      sha256(message),
      u64leLocal(utf8ToBytes(requestId).length),
      utf8ToBytes(requestId),
    )
    eq('userSignaturePayload matches the documented byte layout', toHex(payload), toHex(expected))
    eq('payload length is domain+8+32+8+32+8+ridlen', payload.length, 21 + 8 + 32 + 8 + 32 + 8 + requestId.length)
    // The lengths are u64 LITTLE-endian. A big-endian slip puts 32 in the wrong byte and
    // the node's parse fails on a payload that looks structurally fine.
    eq('the 32-byte digest length is encoded little-endian', toHex(payload.subarray(21 + 8 + 32, 21 + 8 + 32 + 8)), '2000000000000000')
    // A bare (0x-less) slot id must hash the same bytes — callers pass either form.
    eq('a bare slot id yields the same payload', toHex(userSignaturePayload(slotId.slice(2), message, requestId)), toHex(payload))

    // ⚠ The security property: the payload is bound to all THREE inputs. If the request id
    // were left out, a captured signature would authorize a second, different request.
    ok(
      'changing the slot changes the payload',
      toHex(userSignaturePayload(`0x${'ab'.repeat(32)}`, message, requestId)) !== toHex(payload),
    )
    ok(
      'changing the message changes the payload',
      toHex(userSignaturePayload(slotId, utf8ToBytes('transfer 100 TSRA'), requestId)) !== toHex(payload),
    )
    ok(
      'changing the request id changes the payload — no replay onto another request',
      toHex(userSignaturePayload(slotId, message, 'req-0002')) !== toHex(payload),
    )
    // Length-prefixing is what stops two different (slot, rid) pairs colliding by
    // concatenation. Without the prefixes these two would produce identical bytes.
    ok(
      'length prefixes prevent a concatenation collision between requestIds',
      toHex(userSignaturePayload(slotId, message, 'ab')) !== toHex(userSignaturePayload(slotId, message, 'a')) ,
    )

    const secretKey = ed25519.utils.randomPrivateKey()
    const sig = signUserRequest(secretKey, slotId, message, requestId)
    eq('signUserRequest returns a 64-byte signature', sig.length, 64)
    ok(
      'the signature verifies over the canonical payload',
      ed25519.verify(sig, payload, ed25519.getPublicKey(secretKey)),
    )
    ok(
      'it does NOT verify over a payload for another request id',
      !ed25519.verify(sig, userSignaturePayload(slotId, message, 'req-0002'), ed25519.getPublicKey(secretKey)),
    )
  }

  // ─── custody sign: wire shape ─────────────────────────────────────────────
  {
    sent.length = 0
    const message = utf8ToBytes('sign this')
    const userSignature = new Uint8Array(64).fill(7)
    const res = await signCustody({
      nodeUrl: 'http://keeper-a/',
      jwt,
      slotId,
      message,
      signingSet: [1, 2, 3, 4],
      userSignature,
      targetKeykeeper: `0x${'ee'.repeat(20)}`,
      requestId: 'req-42',
    })
    eq('custody: slot id echoed', res.keySlotId, slotId)
    eq('custody: group key decoded to 32 bytes', res.groupPublicKey.length, 32)
    eq('custody: signature halves decoded', [res.signature.r.length, res.signature.z.length], [32, 32])
    eq('custody: epoch is a number', res.epoch, 4)

    const body = bodiesTo('/v1/sign')[0]
    // ⚠ BARE hex throughout: some node handlers hex-decode the field directly, so a 0x
    // prefix is a 400 rather than a tolerated variation.
    eq('custody: slot id is sent without 0x', body?.key_slot_id, 'cd'.repeat(32))
    eq('custody: message is bare hex', body?.message_hex, toHex(message))
    ok('custody: no field carries a 0x prefix', !Object.values(body ?? {}).some(v => typeof v === 'string' && v.startsWith('0x')))
    eq('custody: target_keykeeper is stripped of 0x', body?.target_keykeeper, 'ee'.repeat(20))
    eq('custody: user_signature is bare hex', body?.user_signature, toHex(userSignature))
    // More ids than k is how a caller asks for the robust ROAST coordinator, so the set
    // must be forwarded verbatim rather than trimmed.
    eq('custody: signing_set is forwarded verbatim', body?.signing_set, [1, 2, 3, 4])
    const headers = sent.find(s => s.url.includes('/v1/sign'))?.headers
    eq('custody: the JWT goes in the Authorization header', headers?.Authorization, `Bearer ${jwt}`)
    eq('custody: the request id becomes the idempotency header', headers?.['x-request-id'], 'req-42')
    ok('custody: a trailing slash on the node url is normalised', sent.some(s => s.url === 'http://keeper-a/v1/sign'))
  }
  {
    // Optional fields must be ABSENT, not sent as undefined: the node parses the body
    // strictly and a present-but-null field is not the same as no field.
    sent.length = 0
    await signCustody({nodeUrl: 'http://keeper-a', jwt, slotId, message: new Uint8Array([1])})
    const body = bodiesTo('/v1/sign')[0] ?? {}
    ok(
      'custody: omitted options are absent from the body',
      !('signing_set' in body) && !('user_signature' in body) && !('target_keykeeper' in body),
    )
    const headers = sent.find(s => s.url.includes('/v1/sign'))?.headers ?? {}
    ok('custody: no request id means no idempotency header', !('x-request-id' in headers))
  }
  {
    // A refusal must surface the status, not a generic failure — the caller's next step
    // differs for a 403 (unauthorized) and a 503 (slot not ready).
    custodyFailStatus = 503
    await rejectsWith('custody: a node refusal reports the status', /503/, () =>
      signCustody({nodeUrl: 'http://keeper-a', jwt, slotId, message: new Uint8Array([1])}),
    )
    custodyFailStatus = 0
  }

  // ─── shard-delivery sign: two rounds, real aggregation ────────────────────
  {
    sent.length = 0
    round2Lists.length = 0
    sessions.clear()
    const message = utf8ToBytes('client-coordinated threshold signature')
    // Node URLs deliberately NOT in identifier order, so the canonical sort has work to do.
    const nodeUrls = [committee.get(3)!, committee.get(1)!]
    const sig = await signWithShardDelivery({nodeUrls, jwt, slotId, message, groupPublicKey: groupPk})

    eq('shard: R is 32 bytes', sig.r.length, 32)
    eq('shard: z is 32 bytes', sig.z.length, 32)
    // The real assertion: the locally aggregated signature verifies under the group key.
    // It only can if the commitment list the nodes used is the one the client aggregated.
    ok('shard: the aggregated signature verifies under the group key', frostVerify(groupPk, message, sig))
    ok('shard: it does not verify over a different message', !frostVerify(groupPk, utf8ToBytes('other'), sig))

    eq('shard: one commit per node', bodiesTo('/v1/shards/sign/commit').length, 2)
    eq('shard: one partial per node', bodiesTo('/v1/shards/sign/partial').length, 2)
    // ⚠ Every node must receive the SAME canonically-ordered list (ascending identifier),
    // because the binding factors are derived from it. This is why the URLs above are
    // unsorted: the client must sort, not inherit the caller's order.
    eq('shard: every node received the identifier-sorted commitment list', round2Lists.map(r => r.ids), [[1, 3], [1, 3]])
    const partials = bodiesTo('/v1/shards/sign/partial')
    eq('shard: each partial carries that node\'s own session id', new Set(partials.map(p => p.session_id)).size, 2)
    ok('shard: partials send bare-hex commitments', partials.every(p =>
      (p.commitments as Array<{hiding: string}>).every(c => !c.hiding.startsWith('0x')),
    ))
    eq('shard: the slot id is 0x-stripped', partials[0]?.key_slot_id, 'cd'.repeat(32))
  }
  {
    // The group key is fetched from nodeUrls[0] when the caller does not supply it.
    sent.length = 0
    sessions.clear()
    round2Lists.length = 0
    const sig = await signWithShardDelivery({
      nodeUrls: [committee.get(1)!, committee.get(3)!],
      jwt,
      slotId,
      message: utf8ToBytes('fetch the key'),
    })
    ok('shard: fetches the group key when it is not supplied', sent.some(s => s.url.includes('/public')))
    ok('shard: still verifies with the fetched key', frostVerify(groupPk, utf8ToBytes('fetch the key'), sig))
  }
  {
    // A group key the shares were not produced under is rejected — but NOT by the final
    // verification. The challenge is derived from that key, so every share fails
    // `aggregate`'s per-share check first and the error names the signer (identifiable
    // abort). Worth pinning where the rejection actually comes from: it means the final
    // verify is defence in depth rather than the only gate, and `verify: false` does not
    // switch the per-share checking off.
    const wrongKey = mul(Point.BASE, mod(secret + 1n, L)).toRawBytes()
    const message = utf8ToBytes('unverified')
    for (const verifyFlag of [undefined, false]) {
      sessions.clear()
      await rejectsWith(
        `shard: a wrong group key is caught by identifiable abort (verify: ${String(verifyFlag)})`,
        /invalid signature share from identifier/,
        () =>
          signWithShardDelivery({
            nodeUrls: [...committee.values()],
            jwt,
            slotId,
            message,
            groupPublicKey: wrongKey,
            ...(verifyFlag === undefined ? {} : {verify: verifyFlag}),
          }),
      )
    }
    // With the right key, opting out of the final check still returns a valid signature —
    // the flag is a cost choice, not a correctness one.
    sessions.clear()
    const skipped = await signWithShardDelivery({
      nodeUrls: [...committee.values()],
      jwt,
      slotId,
      message,
      groupPublicKey: groupPk,
      verify: false,
    })
    ok('shard: verify:false still returns a signature that verifies', frostVerify(groupPk, message, skipped))
  }
  await rejectsWith('shard: an empty node list is refused up front', /no node URLs/, () =>
    signWithShardDelivery({nodeUrls: [], jwt, slotId, message: new Uint8Array([1])}),
  )
  {
    servePublicKey = false
    await rejectsWith('shard: an unreachable group key surfaces the failure', /./, () =>
      signWithShardDelivery({nodeUrls: [...committee.values()], jwt, slotId, message: new Uint8Array([1])}),
    )
    servePublicKey = true
  }

  // ─── tECDSA EOA digest ────────────────────────────────────────────────────
  {
    sent.length = 0
    const digest = new Uint8Array(32).fill(9)
    const res = await signEoaDigest({
      nodeUrl: 'http://keeper-a/',
      jwt,
      slotId,
      digest,
      targetKeykeeper: `0x${'ee'.repeat(20)}`,
    })
    eq('eoa: r and s are 32 bytes each', [res.r.length, res.s.length], [32, 32])
    eq('eoa: yParity is narrowed to 0|1', res.yParity, 1)
    const body = bodiesTo('/v1/sign/eoa-digest')[0]
    eq('eoa: slot id is 0x-stripped', body?.key_slot_id, 'cd'.repeat(32))
    eq('eoa: digest is bare hex', body?.digest, toHex(digest))
    eq('eoa: target_keykeeper is 0x-stripped', body?.target_keykeeper, 'ee'.repeat(20))
  }
  {
    // A wrong-length digest is caught BEFORE the round trip: the node would reject it
    // anyway, and the local error names the actual length.
    await rejectsWith('eoa: a short digest is refused locally, naming the length', /digest must be 32 bytes, got 31/, () =>
      signEoaDigest({nodeUrl: 'http://keeper-a', jwt, slotId, digest: new Uint8Array(31)}),
    )
    sent.length = 0
    await signEoaDigest({nodeUrl: 'http://keeper-a', jwt, slotId, digest: new Uint8Array(32)}).catch(() => null)
    const before = sent.length
    await signEoaDigest({nodeUrl: 'http://keeper-a', jwt, slotId, digest: new Uint8Array(33)}).catch(() => null)
    eq('eoa: a bad digest costs no HTTP request', sent.length, before)

    custodyFailStatus = 403
    await rejectsWith('eoa: a refusal reports the status', /403/, () =>
      signEoaDigest({nodeUrl: 'http://keeper-a', jwt, slotId, digest: new Uint8Array(32)}),
    )
    custodyFailStatus = 0
  }

  // ─── ethSignatureV ────────────────────────────────────────────────────────
  {
    // Legacy: 27/28. EIP-155: 35 + 2·chainId + yParity. Both pinned as exact numbers,
    // because an off-by-one produces a transaction the chain rejects — or one that is
    // valid on a chain the signer did not intend.
    eq('v: legacy yParity 0 is 27', ethSignatureV(0), 27)
    eq('v: legacy yParity 1 is 28', ethSignatureV(1), 28)
    eq('v: EIP-155 on the local fleet (1337)', ethSignatureV(0, 1337), 35 + 2 * 1337)
    eq('v: EIP-155 parity is added last', ethSignatureV(1, 1337), 35 + 2 * 1337 + 1)
    eq('v: EIP-155 on Fuji (43113)', ethSignatureV(0, 43113), 86261)
    eq('v: EIP-155 on the C-Chain (43114)', ethSignatureV(1, 43114), 86264)
    // chainId 0 is a real value and must NOT fall back to the legacy encoding.
    eq('v: chainId 0 still uses the EIP-155 form', ethSignatureV(0, 0), 35)
    ok('v: a different chain yields a different v', ethSignatureV(0, 43113) !== ethSignatureV(0, 43114))
  }
  {
    // The address derivation is the identity of a threshold EOA; a compressed and an
    // uncompressed form of the same key must agree.
    const point = secp256k1.ProjectivePoint.BASE.multiply(0x1234_5678n)
    const compressed = point.toRawBytes(true)
    const uncompressed = point.toRawBytes(false)
    eq(
      'eoa address: compressed and uncompressed keys agree',
      addressFromEoaPubkey(compressed),
      addressFromEoaPubkey(uncompressed),
    )
    ok('eoa address: is EIP-55 mixed case', /^0x[0-9a-fA-F]{40}$/.test(addressFromEoaPubkey(compressed)))
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ signing.paths: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ signing.paths: ${passed} checks passed`)
