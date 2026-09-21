// BLS threshold decryption — HTTP clients for the two node paths:
//   • custody        (POST /v1/decrypt)         — node coordinates, returns plaintext
//   • shard-delivery (POST /v1/shards/decrypt)  — CLIENT fans out to k nodes and
//                                                 combines partial shares locally
//
// Ciphertext fields are base64 (standard, padded); key ids are bare hex; the
// `identity` AAD is sent as a UTF-8 string (the node uses its bytes as the AEAD
// AAD / audit key). Identity bytes that aren't valid UTF-8 are not supported on
// the wire.

import {combineDecryptShares, type Ciphertext, type DecryptShare} from '../crypto/kem.js'
import {base64Encode, base64Decode} from '../crypto/envelope.js'
import {bytesToHex as toHex} from '@noble/hashes/utils'
import {httpError} from '../errors.js'

const strip0x = (s: string): string => (s.startsWith('0x') ? s.slice(2) : s)
const base = (u: string): string => u.replace(/\/$/, '')

function ctToWire(ct: Ciphertext): {u: string; nonce: string; aead_ct: string} {
  return {u: base64Encode(ct.u), nonce: base64Encode(ct.nonce), aead_ct: base64Encode(ct.aeadCt)}
}

async function nodePost<T>(
  url: string,
  jwt: string,
  body: unknown,
  requestId?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${jwt}`,
  }
  if (requestId) headers['x-request-id'] = requestId
  const res = await fetch(url, {method: 'POST', headers, body: JSON.stringify(body)})
  if (!res.ok) throw await httpError(res, url, `POST ${url}`)
  return res.json() as Promise<T>
}

// ─── custody decrypt (POST /v1/decrypt) ────────────────────────────────────────

/** A node's BLS identifier + its libp2p PeerId, for the custody decrypting set. */
export interface BlsPeer {
  id: number
  peerId: string
}

export interface DecryptCustodyOpts {
  nodeUrl: string
  jwt: string
  slotId: string
  ciphertext: Ciphertext
  /** AEAD additional-authenticated-data (the identity the envelope was bound to). */
  identity: Uint8Array
  /** BLS identifiers (k..n, distinct) to run the ceremony with. */
  decryptingSet: number[]
  /** The libp2p peers for those identifiers. */
  blsPeers: BlsPeer[]
  /** 64-byte Ed25519 user signature, required iff the slot has an owner pubkey. */
  userSignature?: Uint8Array
  /** Pin the ciphertext epoch; a rotated slot returns 410. */
  ciphertextEpoch?: number
  targetKeykeeper?: string
  requestId?: string
}

/** Decrypt via the custody path: the node runs the whole k-of-n ceremony and
 *  returns the plaintext (one HTTP round-trip). */
export async function decryptCustody(opts: DecryptCustodyOpts): Promise<Uint8Array> {
  const body: Record<string, unknown> = {
    key_slot_id: strip0x(opts.slotId),
    ciphertext: ctToWire(opts.ciphertext),
    identity: new TextDecoder().decode(opts.identity),
    decrypting_set: opts.decryptingSet,
    bls_peers: opts.blsPeers.map(p => ({id: p.id, peer_id: p.peerId})),
  }
  if (opts.userSignature) body.user_signature = toHex(opts.userSignature)
  if (opts.ciphertextEpoch !== undefined) body.ciphertext_epoch = opts.ciphertextEpoch
  if (opts.targetKeykeeper) body.target_keykeeper = strip0x(opts.targetKeykeeper)

  const d = await nodePost<{plaintext: string}>(`${base(opts.nodeUrl)}/v1/decrypt`, opts.jwt, body, opts.requestId)
  return base64Decode(d.plaintext)
}

// ─── shard-delivery decrypt (POST /v1/shards/decrypt) ──────────────────────────

export interface ShardDecryptOpts {
  /** Base URLs of ≥ k nodes to fetch partial decryptions from. */
  nodeUrls: string[]
  jwt: string
  slotId: string
  ciphertext: Ciphertext
  identity: Uint8Array
  ciphertextEpoch?: number
  /** Pairing-verify each share before combining (identifiable abort). Default false. */
  verifyShares?: boolean
}

async function partialDecrypt(
  nodeUrl: string,
  jwt: string,
  slotId: string,
  ct: Ciphertext,
  identity: Uint8Array,
  ciphertextEpoch?: number,
): Promise<DecryptShare> {
  const body: Record<string, unknown> = {
    key_slot_id: strip0x(slotId),
    ciphertext: ctToWire(ct),
    identity: new TextDecoder().decode(identity),
  }
  if (ciphertextEpoch !== undefined) body.ciphertext_epoch = ciphertextEpoch
  const d = await nodePost<{identifier: number; decryption_share: string; verifying_share: string}>(
    `${base(nodeUrl)}/v1/shards/decrypt`,
    jwt,
    body,
  )
  return {
    id: Number(d.identifier),
    decryptionShare: base64Decode(d.decryption_share),
    verifyingShare: base64Decode(d.verifying_share),
  }
}

/** Decrypt via the shard-delivery path: fetch a partial decryption from each
 *  node and combine the shares locally (the master key is never assembled). */
export async function decryptWithShardDelivery(opts: ShardDecryptOpts): Promise<Uint8Array> {
  if (opts.nodeUrls.length === 0) throw new Error('decryptWithShardDelivery: no node URLs')
  const shares = await Promise.all(
    opts.nodeUrls.map(u =>
      partialDecrypt(u, opts.jwt, opts.slotId, opts.ciphertext, opts.identity, opts.ciphertextEpoch),
    ),
  )
  return combineDecryptShares(shares, opts.ciphertext, opts.identity, {
    verify: opts.verifyShares ?? false,
  })
}
