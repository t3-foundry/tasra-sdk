// FROST-Ed25519 signing — HTTP clients for the two node paths:
//   • custody  (POST /v1/sign)                — node coordinates, one round-trip
//   • shard-delivery (POST /v1/shards/sign/{commit,partial})
//                                              — CLIENT coordinates k nodes and
//                                                aggregates locally (frost-crypto)
//
// Bodies use BARE hex (no 0x): some node handlers hex-decode directly. Slot ids
// are sent 0x-stripped; the node tolerates either, the shard message_hex path
// does not.

import {hexToBytes} from '../crypto/hex.js'
import {bytesToHex as toHex, utf8ToBytes, concatBytes} from '@noble/hashes/utils'
import {sha256} from '@noble/hashes/sha256'
import {ed25519} from '@noble/curves/ed25519'
import {fetchMpk} from '../keys/node-client.js'
import {
  aggregate,
  verify,
  type FrostSignature,
  type FrostCommitment,
  type FrostShare,
} from '../crypto/frost.js'
import {httpError} from '../errors.js'

const strip0x = (s: string): string => (s.startsWith('0x') ? s.slice(2) : s)
const base = (u: string): string => u.replace(/\/$/, '')

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true)
  return b
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

// ─── custody sign (POST /v1/sign) ──────────────────────────────────────────────

export interface SignCustodyOpts {
  nodeUrl: string
  jwt: string
  /** 0x-prefixed (or bare) bytes32 slot id. */
  slotId: string
  /** Raw message bytes to sign. */
  message: Uint8Array
  /** Explicit signer set (u16 ids). Omit → node uses 1..k. Passing MORE than k
   *  ids makes the node use the robust ROAST coordinator. */
  signingSet?: number[]
  /** 64-byte Ed25519 user signature — required iff the slot has a registered
   *  owner pubkey. Build with signUserRequest(). */
  userSignature?: Uint8Array
  /** 20-byte operator address to pin (anti-Sybil). */
  targetKeykeeper?: string
  /** Idempotency key. Required when userSignature is set. */
  requestId?: string
}

export interface FrostSignResult {
  keySlotId: string
  /** 32-byte compressed Edwards group public key. */
  groupPublicKey: Uint8Array
  /** The group signature (R, z). Verify with verifyFrostSignature(). */
  signature: FrostSignature
  /** SHA-256 of the signed message, as returned by the node. */
  messageSha256: Uint8Array
  epoch: number
}

/** Sign a message via the custody path: the node runs the whole FROST ceremony
 *  and returns the final group signature (one HTTP round-trip). */
export async function signCustody(opts: SignCustodyOpts): Promise<FrostSignResult> {
  const body: Record<string, unknown> = {
    key_slot_id: strip0x(opts.slotId),
    message_hex: toHex(opts.message),
  }
  if (opts.signingSet) body.signing_set = opts.signingSet
  if (opts.userSignature) body.user_signature = toHex(opts.userSignature)
  if (opts.targetKeykeeper) body.target_keykeeper = strip0x(opts.targetKeykeeper)

  const d = await nodePost<{
    key_slot_id: string
    group_public_key: string
    signature_r: string
    signature_z: string
    message_sha256: string
    epoch?: number
  }>(`${base(opts.nodeUrl)}/v1/sign`, opts.jwt, body, opts.requestId)
  return {
    keySlotId: d.key_slot_id,
    groupPublicKey: hexToBytes(d.group_public_key),
    signature: {r: hexToBytes(d.signature_r), z: hexToBytes(d.signature_z)},
    messageSha256: hexToBytes(d.message_sha256),
    epoch: Number(d.epoch ?? 0),
  }
}

// ─── user-gated signature helper ───────────────────────────────────────────────

const USER_SIG_DOMAIN = 'keykeeper:user-sig:v1'

/** The canonical payload the node verifies for a user-gated sign:
 *  domain ‖ u64_LE(len slot) ‖ slot ‖ u64_LE(32) ‖ SHA256(message) ‖
 *  u64_LE(len requestId) ‖ requestId. */
export function userSignaturePayload(
  slotId: string,
  message: Uint8Array,
  requestId: string,
): Uint8Array {
  const slot = hexToBytes(slotId)
  const rid = utf8ToBytes(requestId)
  return concatBytes(
    utf8ToBytes(USER_SIG_DOMAIN),
    u64le(slot.length),
    slot,
    u64le(32),
    sha256(message),
    u64le(rid.length),
    rid,
  )
}

/** Sign the user-gated payload with the slot owner's 32-byte Ed25519 secret key.
 *  The result goes in SignCustodyOpts.userSignature (also pass the same requestId). */
export function signUserRequest(
  secretKey: Uint8Array,
  slotId: string,
  message: Uint8Array,
  requestId: string,
): Uint8Array {
  return ed25519.sign(userSignaturePayload(slotId, message, requestId), secretKey)
}

// ─── shard-delivery sign (client-coordinated 2-round) ──────────────────────────

export interface ShardSignOpts {
  /** Base URLs of exactly the k chosen committee nodes. */
  nodeUrls: string[]
  jwt: string
  slotId: string
  message: Uint8Array
  /** The slot's 32-byte group public key. Fetched from nodeUrls[0] if omitted. */
  groupPublicKey?: Uint8Array
  /** Verify the aggregate locally before returning (default true). */
  verify?: boolean
}

interface CommitResult extends FrostCommitment {
  nodeUrl: string
  sessionId: string
}

async function commitRound(
  nodeUrl: string,
  jwt: string,
  slotId: string,
  message: Uint8Array,
): Promise<CommitResult> {
  const d = await nodePost<{session_id: string; identifier: number; hiding: string; binding: string}>(
    `${base(nodeUrl)}/v1/shards/sign/commit`,
    jwt,
    {
      key_slot_id: strip0x(slotId),
      message_hex: toHex(message),
    },
  )
  return {
    nodeUrl,
    sessionId: d.session_id,
    identifier: Number(d.identifier),
    hiding: hexToBytes(d.hiding),
    binding: hexToBytes(d.binding),
  }
}

async function partialRound(
  nodeUrl: string,
  jwt: string,
  slotId: string,
  message: Uint8Array,
  sessionId: string,
  commitments: FrostCommitment[],
): Promise<FrostShare> {
  const d = await nodePost<{identifier: number; z: string; verifying_share: string}>(
    `${base(nodeUrl)}/v1/shards/sign/partial`,
    jwt,
    {
      session_id: sessionId,
      key_slot_id: strip0x(slotId),
      message_hex: toHex(message),
      commitments: commitments.map(c => ({
        identifier: c.identifier,
        hiding: toHex(c.hiding),
        binding: toHex(c.binding),
      })),
    },
  )
  return {
    identifier: Number(d.identifier),
    z: hexToBytes(d.z),
    verifyingShare: hexToBytes(d.verifying_share),
  }
}

/**
 * Sign via the shard-delivery path: the CLIENT fans out to k nodes (Round 1
 * commit, Round 2 partial) and aggregates the shares locally into the group
 * signature. The node URLs must be exactly the k committee members.
 */
export async function signWithShardDelivery(opts: ShardSignOpts): Promise<FrostSignature> {
  if (opts.nodeUrls.length === 0) throw new Error('signWithShardDelivery: no node URLs')
  // For a FROST slot, /v1/keys/{id}/public returns the 32-byte Ed25519 group key.
  const groupPublicKey =
    opts.groupPublicKey ?? (await fetchMpk(opts.nodeUrls[0]!, opts.slotId)).mpkBytes

  // Round 1.
  const commits = await Promise.all(
    opts.nodeUrls.map(u => commitRound(u, opts.jwt, opts.slotId, opts.message)),
  )

  // Canonical commitment order — sent to every node AND used to aggregate.
  const commitmentList: FrostCommitment[] = [...commits]
    .sort((a, b) => a.identifier - b.identifier)
    .map(c => ({identifier: c.identifier, hiding: c.hiding, binding: c.binding}))

  // Round 2.
  const shares = await Promise.all(
    commits.map(c =>
      partialRound(c.nodeUrl, opts.jwt, opts.slotId, opts.message, c.sessionId, commitmentList),
    ),
  )

  const sig = aggregate(opts.message, groupPublicKey, commitmentList, shares)
  if (opts.verify !== false && !verify(groupPublicKey, opts.message, sig)) {
    throw new Error('signWithShardDelivery: aggregated signature failed local verification')
  }
  return sig
}
