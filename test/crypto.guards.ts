// Crypto input validation — the guards on the wire parsers and the threshold primitives.
//
// The round trips are covered elsewhere (crypto.roundtrip, ibe.blob, decrypt.shares,
// frost.crypto, the conformance vectors). What was left was the branch that fires on a
// MALFORMED input, and for this module that is the interesting half: an envelope arrives
// over a public feed, a decryption share arrives from a keeper that may be Byzantine, and a
// point arrives as bytes someone else chose.
//
// Three groups are worth more than their line count:
//
//   • THE LENGTH-PREFIX GUARDS in envelope.ts. Every one of them stands between a
//     length field an attacker writes and an allocation. A missing cap is an OOM; a missing
//     "trailing bytes" check lets two different byte strings decode to the same envelope,
//     which is a malleability bug on a format that gets hashed and signed elsewhere.
//
//   • POINT-AT-INFINITY rejection in ibe.ts. The source names the consequence: an infinity
//     D_i "verifies" against an infinity verifying share, defeating identifiable abort, and a
//     U = O ciphertext "decrypts" under every key. Both are accept-anything failures, not
//     crashes, so nothing else would notice.
//
//   • NON-CANONICAL SCALARS in kem.ts. A 32-byte value at or above the field order must be
//     REFUSED, not silently reduced: reduction makes two distinct encodings the same scalar,
//     so a share could be re-encoded and still verify.
//
// Run: tsx test/crypto.guards.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {ed25519} from '@noble/curves/ed25519'
import {
  COMPRESSED_G2_LEN,
  ENVELOPE_VERSION_V1,
  ENVELOPE_VERSION_V2,
  MAX_AEAD_CT_LEN,
  MAX_IDENTITY_LEN,
  NONCE_LEN,
  SLOT_ID_LEN,
} from '../src/crypto/constants.ts'
import {fromBytes, toBytes, encryptEnvelope, type GroupEnvelope} from '../src/crypto/envelope.ts'
import {parseTasraPost} from '../src/crypto/detect.ts'
import {hexToBytes} from '../src/crypto/hex.ts'
import {aggregate, scalarToLe, type FrostCommitment, type FrostShare} from '../src/crypto/frost.ts'
import {
  ibeCombineExtract,
  ibeDecryptWithKey,
  ibeEncrypt,
  ibeVerifyShare,
  type IbeDecryptionShare,
} from '../src/crypto/ibe.ts'
import {
  combineDecryptShares,
  encrypt as kemEncrypt,
  leToScalar,
  verifyDecryptShare,
  type DecryptShare,
} from '../src/crypto/kem.ts'
import {base64Encode} from '../src/crypto/envelope.ts'
import {
  ibeBlobChunkRange,
  ibeBlobDecryptKey,
  ibeDecryptBlobChunk,
  ibeOpenBlob,
  ibeSealBlob,
  ibeUnwrapBlobKey,
} from '../src/crypto/ibe-blob.ts'

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
function throwsWith(name: string, re: RegExp, run: () => unknown): void {
  try {
    run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
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
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)

const {Fr} = bls12_381.fields
const G1 = bls12_381.G1.ProjectivePoint
const G2 = bls12_381.G2.ProjectivePoint

// ─── envelope: the length-prefix guards ───────────────────────────────────────
{
  // A real v2 envelope to mutate. Built through the public encoder so the fixture cannot
  // drift from the format.
  const msk = Fr.create(BigInt('0x1f2e3d4c5b6a79880000000000000000000000000000000000000000000000ab'))
  const mpk = G2.BASE.multiply(msk).toRawBytes(true)
  const slotId = fill(SLOT_ID_LEN, 0xcd)
  const identity = new TextEncoder().encode('did:example:alice')
  const env = encryptEnvelope(slotId, mpk, identity, new TextEncoder().encode('hello'), 7n)
  const wire = toBytes(env)
  ok('a v2 envelope round-trips', fromBytes(wire).epoch === 7n)
  eq('the version byte is v2 when an epoch is present', wire[0], ENVELOPE_VERSION_V2)

  const v1 = toBytes({...env, epoch: null})
  eq('the version byte is v1 without an epoch', v1[0], ENVELOPE_VERSION_V1)
  eq('a v1 envelope reports a null epoch', fromBytes(v1).epoch, null)

  throwsWith('an empty input is refused', /empty input/, () => fromBytes(new Uint8Array()))
  // An unknown version must name the byte: the usual cause is a newer producer, and the
  // reader needs to know which version it could not handle.
  throwsWith('an unknown version byte is named in hex', /unknown version byte 0x9/, () => fromBytes(new Uint8Array([0x09, ...wire.slice(1)])))
  throwsWith('version 0x00 is refused too', /unknown version byte 0x0/, () => fromBytes(new Uint8Array([0x00, 1, 2])))

  for (const [label, version, base] of [['v1', ENVELOPE_VERSION_V1, v1], ['v2', ENVELOPE_VERSION_V2, wire]] as const) {
    // A header shorter than the fixed part cannot be indexed at all.
    throwsWith(`${label}: a truncated header is refused`, new RegExp(`fromBytes\\(${label}\\): truncated header`), () =>
      fromBytes(base.slice(0, 20)),
    )
    // ⚠ The identity length cap. Without it, a 2-byte field an attacker writes drives a
    // slice far past the buffer — and on the producing side, a clamped prefix in front of the
    // real bytes is an envelope nobody can parse.
    const idLenAt = label === 'v1' ? 1 + SLOT_ID_LEN : 1 + SLOT_ID_LEN + 8
    const bigId = new Uint8Array(base)
    new DataView(bigId.buffer).setUint16(idLenAt, MAX_IDENTITY_LEN + 1, true)
    throwsWith(`${label}: an identity_len over the cap is refused, naming the cap`, new RegExp(`identity_len ${MAX_IDENTITY_LEN + 1} exceeds cap ${MAX_IDENTITY_LEN}`), () =>
      fromBytes(bigId),
    )
    // A plausible-but-too-large identity length: inside the cap, past the buffer.
    const overrun = new Uint8Array(base)
    new DataView(overrun.buffer).setUint16(idLenAt, MAX_IDENTITY_LEN, true)
    throwsWith(`${label}: an identity that runs past the buffer is refused`, /truncated identity\/ciphertext/, () =>
      fromBytes(overrun),
    )
    // The AEAD length cap, and the exact-length check behind it.
    const ctLenAt = idLenAt + 2 + identity.length + COMPRESSED_G2_LEN + NONCE_LEN
    const bigCt = new Uint8Array(base)
    new DataView(bigCt.buffer).setUint32(ctLenAt, MAX_AEAD_CT_LEN + 1, true)
    throwsWith(`${label}: an aead_ct_len over the cap is refused`, new RegExp(`aead_ct_len ${MAX_AEAD_CT_LEN + 1} exceeds cap`), () =>
      fromBytes(bigCt),
    )
    // ⚠ The length must be EXACT, not a minimum. Accepting trailing bytes would let two
    // different byte strings decode to the same envelope — malleability on a format that is
    // hashed and signed elsewhere.
    throwsWith(`${label}: trailing bytes are refused`, /trailing bytes or truncated aead_ct/, () =>
      fromBytes(new Uint8Array([...base, 0x00])),
    )
    throwsWith(`${label}: a truncated aead_ct is refused`, /trailing bytes or truncated aead_ct/, () =>
      fromBytes(base.slice(0, base.length - 1)),
    )
    void version
  }

  // v2 only: the epoch is a SIGNED 64-bit field on the wire, so a negative value is
  // representable and must be rejected rather than read as a huge unsigned epoch.
  const negEpoch = new Uint8Array(wire)
  new DataView(negEpoch.buffer).setBigInt64(1 + SLOT_ID_LEN, -1n, true)
  throwsWith('v2: a negative epoch is refused', /epoch -1 is negative/, () => fromBytes(negEpoch))

  // The encoder's own caps, which keep it from producing what the parser would refuse.
  throwsWith('toBytes refuses an epoch past the signed 64-bit range', /does not fit a signed 64-bit integer/, () =>
    toBytes({...env, epoch: 1n << 63n}),
  )
  throwsWith('toBytes refuses a negative epoch', /does not fit a signed 64-bit integer/, () => toBytes({...env, epoch: -1n}))
  throwsWith('toBytes refuses an over-cap identity', new RegExp(`identity length ${MAX_IDENTITY_LEN + 1} exceeds cap`), () =>
    toBytes({...env, identity: fill(MAX_IDENTITY_LEN + 1, 1)}),
  )
  throwsWith('toBytes refuses an over-cap ciphertext', /aead_ct length .* exceeds cap/, () =>
    toBytes({...env, ciphertext: {...env.ciphertext, aeadCt: fill(MAX_AEAD_CT_LEN + 1, 1)}} as GroupEnvelope),
  )

  // encryptEnvelope's preconditions, checked before any crypto runs.
  throwsWith('encryptEnvelope requires a 32-byte slot id', new RegExp(`slot_id must be ${SLOT_ID_LEN} bytes`), () =>
    encryptEnvelope(fill(31, 1), mpk, identity, new Uint8Array([1])),
  )
  throwsWith('encryptEnvelope caps the identity', /identity exceeds cap/, () =>
    encryptEnvelope(slotId, mpk, fill(MAX_IDENTITY_LEN + 1, 1), new Uint8Array([1])),
  )
  throwsWith('encryptEnvelope refuses a negative epoch', /epoch must be non-negative/, () =>
    encryptEnvelope(slotId, mpk, identity, new Uint8Array([1]), -1n),
  )

  // detect: anything that is not a Tasra post is null, not an exception — it runs over every
  // post in a public feed, so a throw would take out the feed.
  eq('a non-Tasra post is null', parseTasraPost('just a normal message'), null)
  eq('an empty string is null', parseTasraPost(''), null)
  ok('a prefixed but corrupt payload is null, not a throw', parseTasraPost('[KK]!!!not-base64!!!') === null)
}

// ─── hex ──────────────────────────────────────────────────────────────────────
{
  eq('hexToBytes accepts a 0x prefix', Array.from(hexToBytes('0x0a0b')), [10, 11])
  eq('hexToBytes accepts a bare string', Array.from(hexToBytes('0a0b')), [10, 11])
  // An odd-length string would silently drop a nibble; the parse is refused instead.
  throwsWith('an odd-length hex string is refused', /odd-length hex string/, () => hexToBytes('0xabc'))
}

// ─── FROST aggregate: the two structural guards ───────────────────────────────
{
  // Real Ed25519 point encodings: the commitment list is decoded before the structural
  // checks, so placeholder bytes would fail as "bad point" and the guard under test would
  // never be reached.
  const edPoint = (k: bigint): Uint8Array => ed25519.Point.BASE.multiply(k).toRawBytes()
  const commitment: FrostCommitment = {identifier: 1, hiding: edPoint(3n), binding: edPoint(5n)}
  const share: FrostShare = {identifier: 1, z: scalarToLe(1n), verifyingShare: edPoint(7n)}
  throwsWith('aggregate refuses an empty commitment list', /no commitments/, () =>
    aggregate(new Uint8Array([1]), edPoint(9n), [], [share]),
  )
  // ⚠ A commitment with no matching share must NAME the identifier. The commitment list is
  // what the binding factors are derived from, so silently skipping one would produce a
  // signature over a different challenge — unattributable.
  //
  // The share-less commitment is the ONLY one here on purpose: the per-share identifiable-abort
  // check runs inside the same loop, in list order, so a commitment that does have a share is
  // rejected for being invalid first and this branch would never be reached.
  throwsWith('aggregate names a commitment with no share', /missing share for identifier 2/, () =>
    aggregate(new Uint8Array([1]), edPoint(9n), [{...commitment, identifier: 2}], [share]),
  )
}

// ─── kem: scalars, shares, combination ────────────────────────────────────────
{
  eq('leToScalar decodes little-endian', leToScalar(new Uint8Array([2, ...new Array<number>(31).fill(0)])), 2n)
  throwsWith('leToScalar requires exactly 32 bytes', /expected 32 bytes, got 31/, () => leToScalar(fill(31, 0)))
  // ⚠ At or above the order must be REFUSED, not reduced. Reduction would make two distinct
  // 32-byte encodings the same scalar, so a share could be re-encoded and still verify.
  const orderLe = new Uint8Array(32)
  let v = Fr.ORDER
  for (let i = 0; i < 32; i++) {
    orderLe[i] = Number(v & 0xffn)
    v >>= 8n
  }
  throwsWith('a scalar equal to the order is refused', /non-canonical scalar/, () => leToScalar(orderLe))
  throwsWith('a scalar above the order is refused', /non-canonical scalar/, () => leToScalar(fill(32, 0xff)))
  // ⚠ Encoded locally against the BLS field, NOT with frost.ts's `scalarToLe` — that one
  // reduces modulo the ED25519 order, so using it here would compare two different fields
  // and the round trip would appear broken when nothing is.
  const blsLe = (n: bigint): Uint8Array => {
    const out = new Uint8Array(32)
    let x = n
    for (let i = 0; i < 32; i++) {
      out[i] = Number(x & 0xffn)
      x >>= 8n
    }
    return out
  }
  eq('the largest canonical scalar is accepted', leToScalar(blsLe(Fr.ORDER - 1n)), Fr.ORDER - 1n)
  eq('zero is canonical', leToScalar(blsLe(0n)), 0n)

  // verifyDecryptShare returns FALSE on malformed input rather than throwing: it is called
  // per share in a fan-out, and one Byzantine keeper must not abort the combine by shape.
  const bogus: DecryptShare = {id: 1, decryptionShare: fill(96, 1), verifyingShare: fill(144, 2)}
  eq('a structurally valid but wrong share is false, not a throw', verifyDecryptShare(bogus, fill(96, 3)), false)
  eq('a share with no verifying share is false', verifyDecryptShare({id: 1, decryptionShare: fill(96, 1)} as DecryptShare, fill(96, 3)), false)
  eq('a wrong-length verifying share is false', verifyDecryptShare({...bogus, verifyingShare: fill(96, 2)}, fill(96, 3)), false)
  eq('undecodable point bytes are false', verifyDecryptShare({...bogus, decryptionShare: fill(96, 0xff)}, fill(96, 3)), false)

  throwsWith('combineDecryptShares refuses an empty share set', /no shares provided/, () =>
    combineDecryptShares([], {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(32, 3)}, new Uint8Array()),
  )
  throwsWith('combineDecryptShares refuses a duplicate identifier', /duplicate identifier 1/, () =>
    combineDecryptShares([bogus, {...bogus}], {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(32, 3)}, new Uint8Array()),
  )
  // ⚠ With `verify`, a bad share must be named — identifiable abort is the whole point, and a
  // combine that failed anonymously would leave the caller unable to say which keeper lied.
  throwsWith('verify:true names the identifier of an invalid share', /invalid decryption share from identifier 1/, () =>
    combineDecryptShares([bogus], {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(32, 3)}, new Uint8Array(), {verify: true}),
  )

  // …and the other side of that branch: with GENUINE shares, verify:true must pass and
  // decrypt. Only testing the rejection would leave "always rejects" indistinguishable from
  // "checks correctly".
  {
    const msk = Fr.create(BigInt('0x33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122'))
    const a1 = Fr.create(BigInt('0x0a0b0c0d0e0f10111213141516171819202122232425262728292a2b2c2d2e2f'))
    const shareOf = (i: number): bigint => Fr.add(msk, Fr.mul(a1, BigInt(i)))
    const mpk = G2.BASE.multiply(msk).toRawBytes(true)
    const identity = new TextEncoder().encode('did:example:group')
    const ct = kemEncrypt(mpk, identity, new TextEncoder().encode('threshold plaintext'))
    const u = G2.fromHex(ct.u)
    // A keeper's share: D_i = sk_i · U, with the dual-group verifying share (96B G2 ‖ 48B G1).
    const share = (i: number): DecryptShare => ({
      id: i,
      decryptionShare: u.multiply(shareOf(i)).toRawBytes(true),
      verifyingShare: new Uint8Array([
        ...G2.BASE.multiply(shareOf(i)).toRawBytes(true),
        ...G1.BASE.multiply(shareOf(i)).toRawBytes(true),
      ]),
    })
    eq('a genuine share passes verifyDecryptShare', verifyDecryptShare(share(1), ct.u), true)
    const plain = combineDecryptShares([share(1), share(2)], ct, identity, {verify: true})
    eq('verify:true combines genuine shares and decrypts', new TextDecoder().decode(plain), 'threshold plaintext')
    // Same shares, verification off — the result must be identical, so the flag is a cost
    // choice rather than a different code path.
    eq(
      'verify:false reaches the same plaintext',
      new TextDecoder().decode(combineDecryptShares([share(1), share(2)], ct, identity)),
      'threshold plaintext',
    )
  }
}

// ─── ibe: point decoding, share verification, combination ─────────────────────
{
  const msk = Fr.create(BigInt('0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe'))
  const a1 = Fr.create(BigInt('0x0a0b0c0d0e0f10111213141516171819202122232425262728292a2b2c2d2e2f'))
  const shareOf = (i: number): bigint => Fr.add(msk, Fr.mul(a1, BigInt(i)))
  const mpk = G2.BASE.multiply(msk).toRawBytes(true)
  const identity = new TextEncoder().encode('did:example:alice/imaging')
  const qId = G1.fromAffine(
    bls12_381.G1.hashToCurve(identity, {DST: 'keykeeper/BLS12381-BF-IBE-HashToG1-v1'}).toAffine(),
  )
  const vs = new Map([1, 2, 3].map(i => [i, G2.BASE.multiply(shareOf(i)).toRawBytes(true)]))
  const partial = (i: number): IbeDecryptionShare => ({identifier: i, value: qId.multiply(shareOf(i)).toRawBytes(true)})

  // A real 2-of-3 extraction still works — the guards must not be over-tight.
  const skId = ibeCombineExtract(vs, [partial(1), partial(2)], identity)
  eq('a valid 2-of-3 extraction produces a 48-byte key', skId.length, 48)

  throwsWith('ibeCombineExtract refuses an empty share set', /no shares/, () => ibeCombineExtract(vs, [], identity))
  throwsWith('ibeCombineExtract refuses a duplicate identifier', /duplicate identifier/, () =>
    ibeCombineExtract(vs, [partial(1), partial(1)], identity),
  )
  // An identifier with no verifying share cannot be checked, so it cannot be trusted.
  throwsWith('an unknown identifier is named', /unknown identifier 9/, () =>
    ibeVerifyShare(vs, identity, {identifier: 9, value: partial(1).value}),
  )
  throwsWith('a share from the wrong identifier is rejected', /invalid share from identifier 2/, () =>
    ibeVerifyShare(vs, identity, {identifier: 2, value: partial(1).value}),
  )

  // Point decoding: length first, then the identity element.
  throwsWith('a G1 share of the wrong length is named', /expected 48 bytes, got 47/, () =>
    ibeVerifyShare(vs, identity, {identifier: 1, value: fill(47, 1)}),
  )
  throwsWith('a G2 verifying share of the wrong length is named', /expected 96 bytes, got 95/, () =>
    ibeVerifyShare(new Map([[1, fill(95, 1)]]), identity, partial(1)),
  )
  // ⚠ POINT AT INFINITY. The source says why: an infinity D_i "verifies" against an infinity
  // verifying share, defeating identifiable abort, and a U = O ciphertext "decrypts" under
  // every key. Both are accept-anything failures nothing else would catch.
  const g1Inf = G1.ZERO.toRawBytes(true)
  const g2Inf = G2.ZERO.toRawBytes(true)
  throwsWith('an infinity G1 share is refused', /point at infinity/, () =>
    ibeVerifyShare(vs, identity, {identifier: 1, value: g1Inf}),
  )
  throwsWith('an infinity G2 verifying share is refused', /point at infinity/, () =>
    ibeVerifyShare(new Map([[1, g2Inf]]), identity, partial(1)),
  )
  throwsWith('an infinity sk_ID is refused', /point at infinity/, () =>
    ibeDecryptWithKey(g1Inf, {u: G2.BASE.toRawBytes(true), nonce: fill(12, 1), aeadCt: fill(32, 2)}, identity),
  )
  throwsWith('an infinity ciphertext U is refused', /point at infinity/, () =>
    ibeDecryptWithKey(skId, {u: g2Inf, nonce: fill(12, 1), aeadCt: fill(32, 2)}, identity),
  )

  // The AEAD nonce length, checked before the cipher is handed a short nonce.
  const ct = ibeEncrypt(mpk, identity, new TextEncoder().encode('secret'))
  eq('a real IBE ciphertext decrypts with the combined key', new TextDecoder().decode(ibeDecryptWithKey(skId, ct, identity)), 'secret')
  throwsWith('a short nonce is refused', /ciphertext.nonce: expected 12 bytes/, () =>
    ibeDecryptWithKey(skId, {...ct, nonce: fill(11, 1)}, identity),
  )
}

// ─── ibe-blob: the chunk bookkeeping guards ───────────────────────────────────
{
  const msk = Fr.create(BigInt('0x1f2e3d4c5b6a79880000000000000000000000000000000000000000000000ab'))
  const a1 = Fr.create(BigInt('0x0a0b0c0d0e0f10111213141516171819202122232425262728292a2b2c2d2e2f'))
  const shareOf = (i: number): bigint => Fr.add(msk, Fr.mul(a1, BigInt(i)))
  const mpk = G2.BASE.multiply(msk).toRawBytes(true)
  const identity = 'did:example:alice/imaging/2026-09'
  const qId = G1.fromAffine(
    bls12_381.G1.hashToCurve(new TextEncoder().encode(identity), {DST: 'keykeeper/BLS12381-BF-IBE-HashToG1-v1'}).toAffine(),
  )
  const vs = new Map([1, 2, 3].map(i => [i, G2.BASE.multiply(shareOf(i)).toRawBytes(true)]))
  const skId = ibeCombineExtract(vs, [1, 2].map(i => ({identifier: i, value: qId.multiply(shareOf(i)).toRawBytes(true)})), new TextEncoder().encode(identity))

  const image = new Uint8Array(2 * 4096 + 100)
  for (let i = 0; i < image.length; i++) image[i] = (i * 7) & 255
  const sealed = await ibeSealBlob(mpk, identity, image, {chunkSize: 4096})
  eq('the sealed header counts three chunks', sealed.header.chunkCount, 3)

  // ⚠ A chunkSize floor: a tiny chunk size means a 16-byte AEAD tag per chunk dominates the
  // payload, and a chunkCount that explodes. Refused rather than accepted as a preference.
  await rejectsWith('a chunkSize below the floor is refused', /chunkSize must be an integer/, () =>
    ibeSealBlob(mpk, identity, image, {chunkSize: 512}),
  )
  await rejectsWith('a fractional chunkSize is refused', /chunkSize must be an integer/, () =>
    ibeSealBlob(mpk, identity, image, {chunkSize: 4096.5}),
  )

  // Chunk indexing is bounds-checked against the HEADER, not the body length, so a caller
  // cannot read past the end by asking for a chunk that was never written.
  throwsWith('a chunk index past the count is refused, naming both', /chunk 3 out of 3/, () =>
    ibeBlobChunkRange(sealed.header, 3),
  )
  throwsWith('a negative chunk index is refused', /chunk -1 out of 3/, () => ibeBlobChunkRange(sealed.header, -1))
  eq('a valid chunk index resolves to a range', ibeBlobChunkRange(sealed.header, 1).plainLength, 4096)
  // The LAST chunk is short, and its range has to reflect that rather than the nominal size.
  eq('the last chunk range is the remainder', ibeBlobChunkRange(sealed.header, 2).plainLength, 100)

  // ⚠ The wrapped key must unwrap to exactly 32 bytes. A DEK of another length means the
  // header came from something else; importing it would fail later as an opaque AEAD error
  // rather than naming the cause. Driven by re-wrapping a 16-byte key under the same identity.
  const shortWrap = ibeEncrypt(mpk, new TextEncoder().encode(identity), new Uint8Array(16))
  throwsWith('a wrapped key that unwraps to the wrong length is named', /wrapped key did not unwrap to 32 bytes/, () =>
    ibeUnwrapBlobKey(skId, {
      ...sealed.header,
      wrappedKey: {
        u: base64Encode(shortWrap.u),
        nonce: base64Encode(shortWrap.nonce),
        aead_ct: base64Encode(shortWrap.aeadCt),
      },
    }),
  )

  // A chunk of the wrong length is a truncated or padded body; decrypting it would surface as
  // an opaque AEAD failure instead of naming the chunk and both lengths.
  const dek = ibeUnwrapBlobKey(skId, sealed.header)
  const key = await ibeBlobDecryptKey(dek)
  const range = ibeBlobChunkRange(sealed.header, 0)
  await rejectsWith('a wrong-length chunk names the chunk and both lengths', /chunk 0 is \d+ bytes, expected \d+/, () =>
    ibeDecryptBlobChunk(key, sealed.header, 0, sealed.body.slice(range.start, range.end - 1)),
  )
  // A correctly-sized chunk from the WRONG position fails authentication, because the AAD
  // binds the index — that is what stops chunks being reordered.
  await rejectsWith('a chunk moved to another index fails authentication', /chunk 1 failed authentication/, () =>
    ibeDecryptBlobChunk(key, sealed.header, 1, sealed.body.slice(range.start, range.end)),
  )
  // And the whole-body length is checked against the header before anything is decrypted.
  await rejectsWith('a body that disagrees with the header is refused', /body is \d+ bytes, header says \d+/, () =>
    ibeOpenBlob(skId, sealed.header, sealed.body.slice(0, sealed.body.length - 1)),
  )
  // The happy path still works with all of that in place.
  const opened = await ibeOpenBlob(skId, sealed.header, sealed.body)
  ok('a sealed blob still round-trips', opened.length === image.length && opened.every((b, i) => b === image[i]))
}

// ─── the WebCrypto requirement ────────────────────────────────────────────────
// LAST, because it takes `crypto.subtle` away from the process to check the guard fires. The
// blob path needs AES-GCM from WebCrypto; on a runtime without it the failure has to name
// what is missing rather than surfacing as "cannot read property importKey of undefined".
{
  const realCrypto = globalThis.crypto
  Object.defineProperty(globalThis, 'crypto', {value: {getRandomValues: realCrypto.getRandomValues.bind(realCrypto)}, configurable: true})
  try {
    await rejectsWith('a runtime with no crypto.subtle is named', /WebCrypto \(crypto\.subtle\) is required for ibe-blob/, () =>
      ibeSealBlob(fill(96, 1), 'did:example:x', new Uint8Array([1])),
    )
  } finally {
    Object.defineProperty(globalThis, 'crypto', {value: realCrypto, configurable: true})
  }
  ok('crypto.subtle is restored afterwards', !!globalThis.crypto.subtle)
}

if (failures.length > 0) {
  console.error(`✗ crypto.guards: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ crypto.guards: ${passed} checks passed`)
