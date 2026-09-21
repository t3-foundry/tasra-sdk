// GroupEnvelope — self-describing wire format for threshold-encrypted chat messages.
// Wire-compatible with the reference envelope implementation.
//
// v0x01 layout (no epoch):
//   [version:1][slot_id:32][identity_len:2 LE][identity:L]
//   [u:96][nonce:12][aead_ct_len:4 LE][aead_ct:M]
//
// v0x02 layout (embedded epoch):
//   [version:1][slot_id:32][epoch:8 LE][identity_len:2 LE][identity:L]
//   [u:96][nonce:12][aead_ct_len:4 LE][aead_ct:M]

import {bls12_381} from '@noble/curves/bls12-381'

import {
  COMPRESSED_G2_LEN,
  ENVELOPE_VERSION_V1,
  ENVELOPE_VERSION_V2,
  MAX_AEAD_CT_LEN,
  MAX_IDENTITY_LEN,
  NONCE_LEN,
  SLOT_ID_LEN,
} from './constants.js'
import {
  assembleKey,
  type Ciphertext,
  decryptWithMasterKey,
  encrypt as kemEncrypt,
  type Shard,
} from './kem.js'

export type {Ciphertext, Shard}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface GroupEnvelope {
  /** On-chain key-slot identifier (bytes32). */
  slotId: Uint8Array
  /** AEAD additional authenticated data — must match at decrypt time. */
  identity: Uint8Array
  /** KEM ciphertext (U, nonce, AEAD output). */
  ciphertext: Ciphertext
  /** Slot epoch this envelope was produced under. Present in v0x02 only. */
  epoch: bigint | null
}

// ─── Serialize ───────────────────────────────────────────────────────────────

/** Largest epoch a v0x02 envelope can carry: the field is a signed 64-bit integer. */
const MAX_EPOCH = (1n << 63n) - 1n

export function toBytes(env: GroupEnvelope): Uint8Array {
  const {slotId, identity, ciphertext, epoch} = env
  const idLen = identity.length
  const ctLen = ciphertext.aeadCt.length
  // Past 2^63 - 1 the epoch would be written negative, an envelope both parsers refuse.
  if (epoch !== null && (epoch < 0n || epoch > MAX_EPOCH)) {
    throw new Error(`toBytes: epoch ${epoch} does not fit a signed 64-bit integer`)
  }
  // A clamped length prefix in front of the full bytes is an envelope nobody can parse. Refuse
  // instead; `encryptEnvelope` never produces one this large.
  if (idLen > MAX_IDENTITY_LEN) {
    throw new Error(`toBytes: identity length ${idLen} exceeds cap ${MAX_IDENTITY_LEN}`)
  }
  if (ctLen > MAX_AEAD_CT_LEN) {
    throw new Error(`toBytes: aead_ct length ${ctLen} exceeds cap ${MAX_AEAD_CT_LEN}`)
  }

  const headerLen =
    epoch !== null
      ? 1 + SLOT_ID_LEN + 8 + 2 // v2: version + slot_id + epoch + id_len
      : 1 + SLOT_ID_LEN + 2 // v1: version + slot_id + id_len

  const total = headerLen + idLen + COMPRESSED_G2_LEN + NONCE_LEN + 4 + ctLen
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  let cur = 0

  if (epoch !== null) {
    out[cur++] = ENVELOPE_VERSION_V2
    out.set(slotId, cur)
    cur += SLOT_ID_LEN
    view.setBigInt64(cur, epoch, true)
    cur += 8
  } else {
    out[cur++] = ENVELOPE_VERSION_V1
    out.set(slotId, cur)
    cur += SLOT_ID_LEN
  }

  view.setUint16(cur, idLen, true)
  cur += 2
  out.set(identity, cur)
  cur += idLen
  out.set(ciphertext.u, cur)
  cur += COMPRESSED_G2_LEN
  out.set(ciphertext.nonce, cur)
  cur += NONCE_LEN
  view.setUint32(cur, ctLen, true)
  cur += 4
  out.set(ciphertext.aeadCt, cur)

  return out
}

// ─── Parse ───────────────────────────────────────────────────────────────────

export function fromBytes(bytes: Uint8Array): GroupEnvelope {
  if (bytes.length === 0) {
    throw new Error('fromBytes: empty input')
  }
  switch (bytes[0]) {
    case ENVELOPE_VERSION_V1:
      return fromBytesV1(bytes)
    case ENVELOPE_VERSION_V2:
      return fromBytesV2(bytes)
    default:
      throw new Error(
        `fromBytes: unknown version byte 0x${(bytes[0] as number).toString(16)}`,
      )
  }
}

function fromBytesV1(bytes: Uint8Array): GroupEnvelope {
  const minLen = 1 + SLOT_ID_LEN + 2 + COMPRESSED_G2_LEN + NONCE_LEN + 4
  if (bytes.length < minLen) {
    throw new Error('fromBytes(v1): truncated header')
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let cur = 1 // skip version byte

  const slotId = bytes.slice(cur, cur + SLOT_ID_LEN)
  cur += SLOT_ID_LEN

  const idLen = view.getUint16(cur, true)
  cur += 2
  if (idLen > MAX_IDENTITY_LEN) {
    throw new Error(
      `fromBytes(v1): identity_len ${idLen} exceeds cap ${MAX_IDENTITY_LEN}`,
    )
  }
  if (bytes.length < cur + idLen + COMPRESSED_G2_LEN + NONCE_LEN + 4) {
    throw new Error('fromBytes(v1): truncated identity/ciphertext')
  }

  const identity = bytes.slice(cur, cur + idLen)
  cur += idLen
  const u = bytes.slice(cur, cur + COMPRESSED_G2_LEN)
  cur += COMPRESSED_G2_LEN
  const nonce = bytes.slice(cur, cur + NONCE_LEN)
  cur += NONCE_LEN

  const ctLen = view.getUint32(cur, true)
  cur += 4
  if (ctLen > MAX_AEAD_CT_LEN) {
    throw new Error(
      `fromBytes(v1): aead_ct_len ${ctLen} exceeds cap ${MAX_AEAD_CT_LEN}`,
    )
  }
  if (bytes.length !== cur + ctLen) {
    throw new Error('fromBytes(v1): trailing bytes or truncated aead_ct')
  }

  const aeadCt = bytes.slice(cur, cur + ctLen)
  return {slotId, identity, ciphertext: {u, nonce, aeadCt}, epoch: null}
}

function fromBytesV2(bytes: Uint8Array): GroupEnvelope {
  const minLen = 1 + SLOT_ID_LEN + 8 + 2 + COMPRESSED_G2_LEN + NONCE_LEN + 4
  if (bytes.length < minLen) {
    throw new Error('fromBytes(v2): truncated header')
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let cur = 1

  const slotId = bytes.slice(cur, cur + SLOT_ID_LEN)
  cur += SLOT_ID_LEN

  const epoch = view.getBigInt64(cur, true)
  cur += 8
  if (epoch < 0n) {
    throw new Error(`fromBytes(v2): epoch ${epoch} is negative`)
  }

  const idLen = view.getUint16(cur, true)
  cur += 2
  if (idLen > MAX_IDENTITY_LEN) {
    throw new Error(
      `fromBytes(v2): identity_len ${idLen} exceeds cap ${MAX_IDENTITY_LEN}`,
    )
  }
  if (bytes.length < cur + idLen + COMPRESSED_G2_LEN + NONCE_LEN + 4) {
    throw new Error('fromBytes(v2): truncated identity/ciphertext')
  }

  const identity = bytes.slice(cur, cur + idLen)
  cur += idLen
  const u = bytes.slice(cur, cur + COMPRESSED_G2_LEN)
  cur += COMPRESSED_G2_LEN
  const nonce = bytes.slice(cur, cur + NONCE_LEN)
  cur += NONCE_LEN

  const ctLen = view.getUint32(cur, true)
  cur += 4
  if (ctLen > MAX_AEAD_CT_LEN) {
    throw new Error(
      `fromBytes(v2): aead_ct_len ${ctLen} exceeds cap ${MAX_AEAD_CT_LEN}`,
    )
  }
  if (bytes.length !== cur + ctLen) {
    throw new Error('fromBytes(v2): trailing bytes or truncated aead_ct')
  }

  const aeadCt = bytes.slice(cur, cur + ctLen)
  return {slotId, identity, ciphertext: {u, nonce, aeadCt}, epoch}
}

// ─── High-level helpers ───────────────────────────────────────────────────────

/**
 * Encrypt `plaintext` to a slot's group key — ChaCha20-Poly1305 under a BLS12-381
 * G2 ElGamal KEM. Local and synchronous: it needs only the slot's **public** key,
 * so no JWT, no node round-trip, and no assembled secret.
 *
 * The three byte-string parameters are easy to transpose — they are, in order:
 * *which slot*, *whose key*, *what to bind*.
 *
 * @param slotId the 32-byte slot id (raw bytes, not hex)
 * @param mpkBytes the slot's 96-byte compressed G2 group public key, as served by
 *   `GET /v1/keys/{slot}/public` (see `fetchMpk`)
 * @param identity additional authenticated data bound into the AEAD. Conventionally
 *   the slot id itself; the managed session defaults to exactly that.
 * @param plaintext the bytes to encrypt
 * @param epoch the current slot epoch, producing a v0x02 envelope; `null` produces
 *   a legacy v0x01 envelope with no epoch binding
 * @returns the envelope — pass through `toBytes()` then `buildTasraText()` for
 *   the opaque `[KK]<base64>` wire form
 * @throws {Error} if `slotId` is not 32 bytes, `identity` exceeds its cap, `plaintext`
 *   exceeds {@link MAX_PLAINTEXT_LEN}, or `epoch` is negative or above 2^63 - 1
 *
 * @example
 * ```ts
 * const {mpkBytes, epoch} = await fetchMpk(nodeUrl, slotHex)
 * const env  = encryptEnvelope(hexToBytes(slotHex), mpkBytes, hexToBytes(slotHex), bytes, BigInt(epoch))
 * const wire = buildTasraText(toBytes(env))   // hand to ANY transport
 * ```
 */
export function encryptEnvelope(
  slotId: Uint8Array,
  mpkBytes: Uint8Array,
  identity: Uint8Array,
  plaintext: Uint8Array,
  epoch: bigint | null = null,
): GroupEnvelope {
  if (slotId.length !== SLOT_ID_LEN) {
    throw new Error(`encryptEnvelope: slot_id must be ${SLOT_ID_LEN} bytes`)
  }
  if (identity.length > MAX_IDENTITY_LEN) {
    throw new Error(`encryptEnvelope: identity exceeds cap ${MAX_IDENTITY_LEN}`)
  }
  if (epoch !== null && (epoch < 0n || epoch > MAX_EPOCH)) {
    throw new Error('encryptEnvelope: epoch must be non-negative and fit a signed 64-bit integer')
  }
  // As in the reference envelope implementation: the AEAD adds a 16-byte tag, and a ciphertext past the cap would never
  // serialise. Fail before encrypting; chunk larger payloads above this layer.
  if (plaintext.length > MAX_PLAINTEXT_LEN) {
    throw new Error(`encryptEnvelope: plaintext exceeds cap ${MAX_PLAINTEXT_LEN} bytes`)
  }

  const ciphertext = kemEncrypt(mpkBytes, identity, plaintext)
  return {slotId, identity, ciphertext, epoch}
}

// Decrypt a GroupEnvelope using an assembled master secret key.
// mskBytes: 32-byte LE scalar (output of assembleKey).
export function decryptEnvelope(
  env: GroupEnvelope,
  mskBytes: Uint8Array,
): Uint8Array {
  return decryptWithMasterKey(mskBytes, env.ciphertext, env.identity)
}

// Convenience: parse base64-encoded envelope bytes then decrypt.
export function decryptEnvelopeBase64(
  envelopeBase64: string,
  mskBytes: Uint8Array,
): Uint8Array {
  const bytes = base64Decode(envelopeBase64)
  const env = fromBytes(bytes)
  return decryptEnvelope(env, mskBytes)
}

// ─── Base64 helpers ───────────────────────────────────────────────────────────

// Bytes per `String.fromCharCode` call. Passing every byte as a separate argument
// (`fromCharCode(...bytes)`) overflows the call stack once the input passes ~124 KiB on
// Node 24 (engines differ), so large envelopes and ciphertexts failed to encode.
const BASE64_CHUNK = 0x8000

/** Largest plaintext one envelope carries: the AEAD ciphertext cap minus the 16-byte tag. */
export const MAX_PLAINTEXT_LEN = MAX_AEAD_CT_LEN - 16

export function base64Encode(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + BASE64_CHUNK))
  }
  return btoa(binary)
}

export function base64Decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

// ─── Re-export low-level ops for callers that need them ───────────────────────

export {assembleKey, decryptWithMasterKey, kemEncrypt}

// Re-export G2 public key parsing helper.
export function mpkFromBase64(base64: string): Uint8Array {
  return base64Decode(base64)
}

// Parse a G2 compressed point and return it as a noble G2 point (for DKG-level work).
export function parseMpk(bytes: Uint8Array) {
  return bls12_381.G2.ProjectivePoint.fromHex(bytes)
}
