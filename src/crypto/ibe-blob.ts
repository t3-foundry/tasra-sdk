// Identity-scoped ENVELOPE encryption for large objects (images, scans, documents).
//
// `ibeEncrypt` is a single-shot AEAD over the whole message: right for a record of a few
// kilobytes, wrong for a 500 MB CT series (whole-message in memory, no random access, and a
// JavaScript ChaCha20). This module keeps the identity binding where it is — a BF-IBE
// ciphertext — but applies it to a 32-byte DATA KEY, and encrypts the body with that key as
// AES-256-GCM CHUNKS through WebCrypto (hardware-speed in every browser and in Node ≥ 20):
//
//   header = { v, blobId, identity, contentType, size, chunkSize, chunkCount, wrappedKey }
//   body   = chunk_0 ‖ chunk_1 ‖ … each = AES-256-GCM(dek, nonce_i, aad_i, plain_i) ‖ tag(16)
//   nonce_i = blobId[0..8] ‖ be32(i)          (the data key is per object, so this is unique)
//   aad_i   = "keykeeper/ibe-blob/v1" ‖ blobId ‖ be32(i) ‖ last(1) ‖ identity
//
// Each chunk is independently decryptable (range requests, streaming), and the associated
// data binds every chunk to its position, to "is this the last one" (truncation fails), and to
// the object + identity (a chunk cannot be moved between blobs or identities). Only the
// wrapped key ever needs an identity key: unwrapping is one pairing regardless of size, and
// one extracted `sk_ID` opens every object written to that identity.
//
// ⚠ Confidentiality only. Encrypting to an identity is permissionless (anyone holding the
// class public key can do it), so WHO produced a blob needs a separate signature by the
// producer over `sha256(body)` + the header — an application manifest, not this layer.

import {randomBytes} from '@noble/hashes/utils'
import {sha256} from '@noble/hashes/sha256'
import {base64Encode, base64Decode} from './envelope.js'
import {ibeDecryptWithKey, ibeEncrypt, type IbeCiphertext} from './ibe.js'

export const IBE_BLOB_VERSION = 1
export const IBE_BLOB_AAD_DOMAIN = 'keykeeper/ibe-blob/v1'
/** Default chunk: 1 MiB of plaintext (+16-byte tag on the wire). */
export const IBE_BLOB_DEFAULT_CHUNK = 1024 * 1024
const TAG = 16

/** The clear header stored beside the ciphertext body. Nothing in it is secret. */
export interface IbeBlobHeader {
  v: 1
  /** 16 random bytes, base64 — the object's identity for the chunk binding. */
  blobId: string
  /** The IBE identity the data key is wrapped to. */
  identity: string
  contentType: string
  /** Plaintext size in bytes. */
  size: number
  chunkSize: number
  chunkCount: number
  /** `ibeEncrypt(mpk, identity, dek)` — the wire shape of `bls::ibe::Ciphertext`. */
  wrappedKey: {u: string; nonce: string; aead_ct: string}
}

export interface SealedBlob {
  header: IbeBlobHeader
  /** The concatenated encrypted chunks. */
  body: Uint8Array
}

const utf8 = (s: string) => new TextEncoder().encode(s)
const be32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])
// Takes an array, never spread arguments: a blob body has one part per chunk, and a call with
// ~100k arguments (a large blob at the minimum chunk size) overflows the stack.
function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
/** A copy backed by a plain ArrayBuffer — WebCrypto's `BufferSource` refuses views over
 *  `ArrayBufferLike` (a possibly-shared buffer) at the type level. */
function buf(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(u8)
}
function subtle(): SubtleCrypto {
  const s = (globalThis.crypto as Crypto | undefined)?.subtle
  if (!s) throw new Error('WebCrypto (crypto.subtle) is required for ibe-blob')
  return s
}
function nonceFor(blobId: Uint8Array, index: number): Uint8Array {
  return concat([blobId.subarray(0, 8), be32(index)])
}
function aadFor(blobId: Uint8Array, index: number, last: boolean, identity: string): Uint8Array {
  return concat([utf8(IBE_BLOB_AAD_DOMAIN), blobId, be32(index), new Uint8Array([last ? 1 : 0]), utf8(identity)])
}

/** The byte range of chunk `i` inside the body — for range requests and streaming. */
export function ibeBlobChunkRange(header: IbeBlobHeader, index: number): {start: number; end: number; plainLength: number} {
  if (index < 0 || index >= header.chunkCount) throw new RangeError(`chunk ${index} out of ${header.chunkCount}`)
  const start = index * (header.chunkSize + TAG)
  const plainLength = index === header.chunkCount - 1 ? header.size - index * header.chunkSize : header.chunkSize
  return {start, end: start + plainLength + TAG, plainLength}
}

/**
 * Seal `plaintext` to `identity` under the slot's master public key: a fresh data key,
 * IBE-wrapped, and the body as independently-decryptable AES-256-GCM chunks. Offline and
 * permissionless, like `ibeEncrypt`.
 */
export async function ibeSealBlob(
  mpkBytes: Uint8Array,
  identity: string,
  plaintext: Uint8Array,
  opts: {contentType?: string; chunkSize?: number} = {},
): Promise<SealedBlob> {
  const chunkSize = opts.chunkSize ?? IBE_BLOB_DEFAULT_CHUNK
  if (!Number.isInteger(chunkSize) || chunkSize < 1024) throw new RangeError('chunkSize must be an integer ≥ 1024')
  const blobId = randomBytes(16)
  const dek = randomBytes(32)
  const key = await subtle().importKey('raw', buf(dek), {name: 'AES-GCM'}, false, ['encrypt'])
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / chunkSize))
  const parts: Uint8Array[] = []
  for (let i = 0; i < chunkCount; i++) {
    const plain = plaintext.subarray(i * chunkSize, Math.min(plaintext.length, (i + 1) * chunkSize))
    const ct = await subtle().encrypt({name: 'AES-GCM', iv: buf(nonceFor(blobId, i)), additionalData: buf(aadFor(blobId, i, i === chunkCount - 1, identity)), tagLength: 128}, key, buf(plain))
    parts.push(new Uint8Array(ct))
  }
  const wrapped: IbeCiphertext = ibeEncrypt(mpkBytes, utf8(identity), dek)
  dek.fill(0)
  return {
    header: {
      v: IBE_BLOB_VERSION,
      blobId: base64Encode(blobId),
      identity,
      contentType: opts.contentType ?? 'application/octet-stream',
      size: plaintext.length,
      chunkSize,
      chunkCount,
      wrappedKey: {u: base64Encode(wrapped.u), nonce: base64Encode(wrapped.nonce), aead_ct: base64Encode(wrapped.aeadCt)},
    },
    body: concat(parts),
  }
}

/** The blob's IBE-wrapped data key as an `IbeCiphertext` (what `ibeDecryptWithKey` takes). */
export function ibeBlobWrappedKey(header: IbeBlobHeader): IbeCiphertext {
  return {u: base64Decode(header.wrappedKey.u), nonce: base64Decode(header.wrappedKey.nonce), aeadCt: base64Decode(header.wrappedKey.aead_ct)}
}

/**
 * Unwrap the data key with the identity's extracted key `sk_ID` (48-byte compressed G1 —
 * `ibeCombineExtract`'s output). One pairing; the caller keeps the returned key in memory only
 * as long as it decrypts, then zeroizes it.
 */
export function ibeUnwrapBlobKey(skIdBytes: Uint8Array, header: IbeBlobHeader): Uint8Array {
  const dek = ibeDecryptWithKey(skIdBytes, ibeBlobWrappedKey(header), utf8(header.identity))
  if (dek.length !== 32) throw new Error('ibe-blob: wrapped key did not unwrap to 32 bytes')
  return dek
}

/** A WebCrypto key for `dek`, importable once per blob and reused across chunks. */
export async function ibeBlobDecryptKey(dek: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey('raw', buf(dek), {name: 'AES-GCM'}, false, ['decrypt'])
}

/** Decrypt one chunk (its exact body slice, see {@link ibeBlobChunkRange}). */
export async function ibeDecryptBlobChunk(key: CryptoKey, header: IbeBlobHeader, index: number, chunk: Uint8Array): Promise<Uint8Array> {
  const blobId = base64Decode(header.blobId)
  const {plainLength} = ibeBlobChunkRange(header, index)
  if (chunk.length !== plainLength + TAG) throw new Error(`ibe-blob: chunk ${index} is ${chunk.length} bytes, expected ${plainLength + TAG}`)
  try {
    const plain = await subtle().decrypt({name: 'AES-GCM', iv: buf(nonceFor(blobId, index)), additionalData: buf(aadFor(blobId, index, index === header.chunkCount - 1, header.identity)), tagLength: 128}, key, buf(chunk))
    return new Uint8Array(plain)
  } catch {
    throw new Error(`ibe-blob: chunk ${index} failed authentication (tampered, reordered, or not this blob)`)
  }
}

/**
 * Open a whole sealed blob with `sk_ID`: unwrap the key, decrypt every chunk, return the
 * plaintext. Streaming consumers use `ibeUnwrapBlobKey` + `ibeDecryptBlobChunk` per range.
 */
export async function ibeOpenBlob(skIdBytes: Uint8Array, header: IbeBlobHeader, body: Uint8Array): Promise<Uint8Array> {
  const expected = header.size + header.chunkCount * TAG
  if (body.length !== expected) throw new Error(`ibe-blob: body is ${body.length} bytes, header says ${expected}`)
  const dek = ibeUnwrapBlobKey(skIdBytes, header)
  try {
    const key = await ibeBlobDecryptKey(dek)
    const out = new Uint8Array(header.size)
    for (let i = 0; i < header.chunkCount; i++) {
      const {start, end} = ibeBlobChunkRange(header, i)
      out.set(await ibeDecryptBlobChunk(key, header, i, body.subarray(start, end)), i * header.chunkSize)
    }
    return out
  } finally {
    dek.fill(0)
  }
}

/** `sha256(body)` — what a producer signs in its manifest so a reader can check provenance. */
export function ibeBlobDigest(body: Uint8Array): Uint8Array {
  return sha256(body)
}
