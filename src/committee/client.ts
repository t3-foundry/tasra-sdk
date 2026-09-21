// Committee-mode HTTP orchestration — the glue around the pure token
// crypto in ./committee.ts. Three pieces:
//   • committeeAuthorize() — POST a VP to ONE verifier's /v1/committee-authorize,
//     which (if that verifier is in the per-request draw) returns its ed25519
//     signature over the canonical token hash.
//   • gatherCommitteeToken() — fan out to the candidate verifiers, collect a
//     quorum of signatures, and assemble the compound token. Self-checks that our
//     canonical hash equals the hash the verifiers signed.
//   • committeeSign() / committeeDecrypt() — POST the assembled token (in the
//     BODY, no auth header) to the keeper's /v1/committee/{sign,decrypt}.

import {hexToBytes, bytesToHex} from '../crypto/hex.js'
import {httpError, TasraHttpError, ThresholdNotMetError} from '../errors.js'
import {bytesToHex as bareHex} from '@noble/hashes/utils'
import {
  assembleCompoundToken,
  compoundTokenHash,
  type CompoundTokenPayload,
  type CompoundTokenWire,
  type CommitteeSignature,
  type TokenType, bindingFromWire} from './token.js'
import {base64Encode, base64Decode} from '../crypto/envelope.js'
import type {Ciphertext} from '../crypto/kem.js'
import type {FrostSignResult} from '../signing/frost.js'
import type {BlsPeer} from '../decryption/client.js'

const strip0x = (s: string): string => (s.startsWith('0x') ? s.slice(2) : s)
const base = (u: string): string => u.replace(/\/$/, '')

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

function ctToWire(ct: Ciphertext): {u: string; nonce: string; aead_ct: string} {
  return {u: base64Encode(ct.u), nonce: base64Encode(ct.nonce), aead_ct: base64Encode(ct.aeadCt)}
}

/** Trustless verifier-set inclusion proof, passed to the keeper. */
export interface VerifierProof {
  verifierIndex: number
  /** 20-byte operator address (hex). */
  operator: string
  /** 32-byte ed25519 pubkey (hex). */
  pubkey: string
  /** Sorted-pair keccak Merkle proof (each 32-byte hex). */
  proof: string[]
}

function proofsToWire(proofs: VerifierProof[]): unknown[] {
  return proofs.map(p => ({
    verifier_index: p.verifierIndex,
    operator: strip0x(p.operator),
    pubkey: strip0x(p.pubkey),
    proof: p.proof.map(strip0x),
  }))
}

// ─── verifier: POST /v1/committee-authorize ────────────────────────────────────

/**
 * A verifier refused to co-sign a committee token. Extends
 * {@link TasraHttpError}, so `.status`, `.url`, `.body`, and `.retryable` are
 * all available and `isAuthDenied()` recognises a 401/403 here too.
 *
 * Distinct from a generic HTTP error because the committee flow polls several
 * verifiers and tolerates individual refusals as long as a quorum co-signs — see
 * {@link ThresholdNotMetError} for the failure that means the quorum was missed.
 */
export class CommitteeAuthorizeError extends TasraHttpError {
  constructor(status: number, message: string, opts?: {url?: string; body?: string}) {
    super({status, url: opts?.url ?? '', body: opts?.body, message})
  }
}

// ⚠ There is deliberately no rule field. The verifier fetches the slot's confidential
// rule from a keeper by `slotId` and checks it against the on-chain `ruleCommitment`, so
// a caller cannot present a permissive rule of its own choosing and have a committee
// authorize against it.
export interface CommitteeAuthorizeBody {
  /** Holder DID (the credentials' subject). */
  holder: string
  /** Compact-JWS verifiable credentials. */
  credentials: string[]
  /** F1/F4: holder proof-of-possession. Build via `createHolderProof`
   *  (bind it to `slotId`). Empty string ⇒ omitted from the wire, which only a
   *  verifier with `require_holder_binding = false` accepts. */
  holderProof: string
  tokenType: TokenType
  /** 32-byte on-chain beacon seed. */
  seed: Uint8Array
  epoch: number | bigint
  /** 32-byte slot id. */
  slotId: Uint8Array
  /** Active verifier-set size at `epoch`. */
  registrySize: number
  /** The slot's verifierPolicy committee size. */
  committee: number
  iat: number | bigint
  exp: number | bigint
  /**
   * The requested IBE identity, present **iff** the operation is
   * identity-scoped. The committee evaluates the slot's scope binding against it and
   * folds `keccak256(identity)` into the signed token — a quorum attests THIS identity
   * and the token is unusable for any other. Omit for every other operation.
   */
  identity?: string
  /**
   * request binding: the preimage every drawn verifier re-derives `request_hash`
   * and the KB-JWT nonce from. Send it whenever the keeper runs `require_request_binding`
   * (production posture): the reply then carries `request_hash` + `binding`, which the
   * gathered token must include or the keeper refuses it. Absent = legacy (unbound) path.
   */
  binding?: RequestBindingPreimage
}

/** The six fields the Verifier Agent fans out (`FanoutRequest`); `random` is the per-request nonce salt. */
export interface RequestBindingPreimage {
  chainId: number | bigint
  action: 'sign' | 'decrypt' | 'ibe-extract' | 'dual-approve'
  /** 32 bytes — the per-action digest (`payloadDigestFor`). */
  payloadDigest: Uint8Array
  /** 32 random bytes; the KB-JWT nonce derives from (request_hash, random). */
  random: Uint8Array
  /** The JAR `client_id` the KB-JWT's `aud` must equal. */
  clientId: string
  description?: string
}

export interface CommitteeAuthorizeReply {
  verifierIndex: number
  tokenHash: Uint8Array
  vpHash: Uint8Array
  /** `keccak256` of the holder this verifier authenticated — inside the signed bytes. */
  holderHash: Uint8Array
  /** `keccak256` of the RAW rule this verifier evaluated (UNSALTED) — what the keeper
   *  binds against its own `keccak256(rule)`. */
  ruleHash: Uint8Array
  /** the identity binding this verifier signed — present iff the request
   *  carried `identity`. Inside the signed bytes, like `holderHash`. */
  identityHash?: Uint8Array
  signature: Uint8Array
  /** The full ordered committee draw, so the caller knows whom else to ask. */
  committeeIndexes: number[]
  /**
   * The slot's `ruleVersion` this authorization was evaluated against.
   *
   * ⚠ Diagnostic, not a gate. The keeper binds `ruleHash` to its own rule hash,
   * so a token minted under a superseded policy is refused there
   * whatever this says. Its value is that it explains the refusal: without it, a
   * token minted moments before an amendment activates is rejected with nothing
   * to distinguish it from a genuinely unauthorized request.
   *
   * `undefined` from a verifier that predates rule versioning.
   */
  ruleVersion?: number
  /** present when the request carried a binding preimage; inside the signed bytes. */
  requestHash?: Uint8Array
  /** binding strength byte (`bindingFromWire`); `0x00` when the verifier declared none. */
  binding: number
}

function authorizeWire(b: CommitteeAuthorizeBody): Record<string, unknown> {
  return {
    holder: b.holder,
    credentials: b.credentials,
    // Omit rather than send "": the server field is an Option, and an empty
    // string is a value that fails parsing rather than an absent proof.
    ...(b.holderProof ? {holder_proof: b.holderProof} : {}),
    token_type: b.tokenType,
    seed: bytesToHex(b.seed),
    epoch: Number(b.epoch),
    slot_id: bytesToHex(b.slotId),
    registry_size: b.registrySize,
    committee: b.committee,
    iat: Number(b.iat),
    exp: Number(b.exp),
    ...(b.identity !== undefined ? {identity: b.identity} : {}),
    ...(b.binding
      ? {
          chain_id: Number(b.binding.chainId),
          action: b.binding.action,
          payload_digest: bytesToHex(b.binding.payloadDigest),
          random: bytesToHex(b.binding.random),
          client_id: b.binding.clientId,
          ...(b.binding.description !== undefined ? {description: b.binding.description} : {}),
        }
      : {}),
  }
}

/** Ask one verifier to authorize the request. Throws CommitteeAuthorizeError
 *  (with `.status`) on a non-2xx — notably 403 when this verifier wasn't drawn. */
export async function committeeAuthorize(
  verifierUrl: string,
  body: CommitteeAuthorizeBody,
): Promise<CommitteeAuthorizeReply> {
  // ⚠ A SECOND copy of this guard used to live here as well as in
  // `requestCommitteeToken`, and relaxing only the outer one left the inner one
  // refusing every request — the duplicated policy is why. The rule belongs at
  // ONE layer: the caller decides (and states it), this function transmits.
  //
  // The server field is an `Option` and a verifier with
  // `require_holder_binding = false` accepts the request without a proof, so a
  // hard refusal here makes a valid deployment unreachable.
  if (body.holderProof === undefined) {
    throw new Error(
      'committeeAuthorize: holderProof must be a string (pass "" only when the verifier runs ' +
        'require_holder_binding = false)',
    )
  }
  const url = `${base(verifierUrl)}/v1/committee-authorize`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(authorizeWire(body)),
  })
  if (!res.ok) {
    const detail = (await res.text().catch(() => '')).slice(0, 200)
    throw new CommitteeAuthorizeError(
      res.status,
      `committee-authorize → HTTP ${res.status}${detail ? `: ${detail}` : ''}`,
      {url, body: detail},
    )
  }
  const d = (await res.json()) as {
    verifier_index: number
    token_hash: string
    vp_hash: string
    holder_hash: string
    rule_hash: string
    /** Present iff the request carried `identity`. */
    identity_hash?: string
    signature: string
    committee_indexes: number[]
    /** Absent from a verifier that predates rule versioning. */
    rule_version?: number
    /** Present when the request carried the binding preimage. */
    request_hash?: string
    binding?: string
  }
  return {
    verifierIndex: Number(d.verifier_index),
    tokenHash: hexToBytes(d.token_hash),
    vpHash: hexToBytes(d.vp_hash),
    holderHash: hexToBytes(d.holder_hash),
    ruleHash: hexToBytes(d.rule_hash),
    ...(typeof d.identity_hash === 'string' ? {identityHash: hexToBytes(d.identity_hash)} : {}),
    ...(typeof d.request_hash === 'string' ? {requestHash: hexToBytes(d.request_hash)} : {}),
    binding: bindingFromWire(d.binding),
    signature: hexToBytes(d.signature),
    committeeIndexes: d.committee_indexes,
    ruleVersion: typeof d.rule_version === 'number' ? d.rule_version : undefined,
  }
}

// ─── coordinator: gather a quorum + assemble the token ─────────────────────────

export interface GatherCommitteeTokenOpts {
  /** Candidate verifiers to ask (index → base URL). Asking the whole registry is
   *  fine — non-drawn verifiers reply 403 and are skipped. */
  verifiers: Array<{index: number; url: string}>
  authorize: CommitteeAuthorizeBody
  /** The slot's verifierPolicy quorum (minimum distinct committee signatures). */
  quorum: number
  /**
   * Observe the raw replies. Added rather than widening the return type, which
   * would break every existing caller for a diagnostic.
   *
   * `reference` is the reply whose `vpHash`/`ruleHash` were used to build the
   * token — so anything read from it describes the SAME evaluation the token
   * carries, which matters when verifiers straddle an amendment and disagree
   * about the rule version.
   */
  onReplies?: (all: CommitteeAuthorizeReply[], reference: CommitteeAuthorizeReply) => void
  /**
   * A holder proof PER VERIFIER, overriding `authorize.holderProof` for that verifier.
   *
   * ⚠ ONE HOLDER PROOF DOES NOT SERVE A COMMITTEE. A proof is bound to a nonce that is a
   * row in ONE verifier's store and `consume` is an atomic take — so one proof fanned to k
   * verifiers is spent by whichever answers first and the rest 401 under
   * `require_holder_binding`. This callback lets the caller mint one proof per drawn
   * verifier (nonce from THAT verifier, its audience, the same credentials + slot). Called
   * once per candidate verifier, concurrently; a rejection fails that verifier only, so a
   * quorum can still be reached from the others.
   */
  holderProofFor?: (verifier: {index: number; url: string}) => Promise<string> | string
}

/**
 * Fan out to the candidate verifiers, collect signatures from the drawn committee
 * until quorum, and assemble the compound token. Verifies that our locally
 * recomputed canonical token hash equals the hash the verifiers signed (a built-in
 * encoding cross-check). Returns the wire token to POST to the keeper.
 */
export async function gatherCommitteeToken(opts: GatherCommitteeTokenOpts): Promise<CompoundTokenWire> {
  const settled = await Promise.allSettled(
    opts.verifiers.map(async v => {
      const body = opts.holderProofFor
        ? {...opts.authorize, holderProof: await opts.holderProofFor(v)}
        : opts.authorize
      return committeeAuthorize(v.url, body)
    }),
  )
  const replies = settled
    .filter((r): r is PromiseFulfilledResult<CommitteeAuthorizeReply> => r.status === 'fulfilled')
    .map(r => r.value)
  if (replies.length === 0) {
    // ⚠ Report WHY. "no verifier authorized the request" with the reasons
    // discarded is the least actionable error this library can produce: every
    // cause — a stale credential, an undrawn verifier, a seed/epoch mismatch,
    // a verifier that is simply down — looks identical, and each has a
    // completely different fix.
    const why = settled
      .map((r, i) => {
        const who = opts.verifiers[i]?.url ?? `#${i}`
        if (r.status === 'fulfilled') return null
        const e = r.reason as {status?: number; message?: string}
        return `${who}: ${e?.status ? `HTTP ${e.status} ` : ''}${e?.message ?? String(r.reason)}`
      })
      .filter(Boolean)
      .join('; ')
    throw new Error(`gatherCommitteeToken: no verifier authorized the request — ${why}`)
  }

  const ref = replies[0]!
  opts.onReplies?.(replies, ref)
  const committeeIndexes = ref.committeeIndexes
  const inCommittee = new Set(committeeIndexes)

  // distinct signatures from drawn committee members
  const sigByIndex = new Map<number, CommitteeSignature>()
  for (const r of replies) {
    if (inCommittee.has(r.verifierIndex)) {
      sigByIndex.set(r.verifierIndex, {verifierIndex: r.verifierIndex, signature: r.signature})
    }
  }
  if (sigByIndex.size < opts.quorum) {
    // Typed, because this is exactly the failure `CommitteeAuthorizeError`'s doc points a caller at:
    // individual refusals are tolerated, a missed quorum is not. Retryable — a verifier that was slow
    // or restarting answers the next attempt, and the drawn committee is redrawn per request.
    throw new ThresholdNotMetError({
      got: sigByIndex.size,
      need: opts.quorum,
      reasons: replies
        .filter(r => !inCommittee.has(r.verifierIndex))
        .map(r => `verifier #${r.verifierIndex} answered but was not in the drawn committee`),
      message: `gatherCommitteeToken: quorum not met (${sigByIndex.size}/${opts.quorum} from the drawn committee)`,
    })
  }

  const payload: CompoundTokenPayload = {
    tokenType: opts.authorize.tokenType,
    seed: opts.authorize.seed,
    epoch: opts.authorize.epoch,
    slotId: opts.authorize.slotId,
    vpHash: ref.vpHash,
    holderHash: ref.holderHash,
    ruleHash: ref.ruleHash,
    // From the reference reply, like ruleHash — the hash cross-check below
    // then proves the whole committee signed over the SAME identity binding.
    ...(ref.identityHash !== undefined ? {identityHash: ref.identityHash} : {}),
    // The binding the reference verifier declared; the hash cross-check below proves
    // every signer signed the SAME request_hash + binding byte.
    ...(ref.requestHash !== undefined ? {requestHash: ref.requestHash} : {}),
    binding: ref.binding,
    verifierIndexes: committeeIndexes,
    iat: opts.authorize.iat,
    exp: opts.authorize.exp,
  }
  if (!bytesEqual(compoundTokenHash(payload), ref.tokenHash)) {
    throw new Error('gatherCommitteeToken: canonical token hash disagrees with the verifier (encoding mismatch)')
  }
  return assembleCompoundToken(payload, [...sigByIndex.values()])
}

// ─── keeper: POST /v1/committee/{sign,decrypt} (token in body, no auth header) ──

export interface CommitteeSignOpts {
  nodeUrl: string
  committeeToken: CompoundTokenWire
  message: Uint8Array
  signingSet?: number[]
  userSignature?: Uint8Array
  targetKeykeeper?: string
  verifierProofs?: VerifierProof[]
  /** client request signature: the client's 32-byte ed25519 pubkey + its 64-byte
   *  signature over `clientBindingHash(slotId, tokenHash)`. Both or neither. */
  clientPubkey?: Uint8Array
  clientSignature?: Uint8Array
}

/** Sign via committee authorization. The slot id is taken from the token. */
export async function committeeSign(opts: CommitteeSignOpts): Promise<FrostSignResult> {
  const body: Record<string, unknown> = {
    committee_token: opts.committeeToken,
    message_hex: bareHex(opts.message),
  }
  if (opts.signingSet) body.signing_set = opts.signingSet
  if (opts.userSignature) body.user_signature = bareHex(opts.userSignature)
  if (opts.targetKeykeeper) body.target_keykeeper = strip0x(opts.targetKeykeeper)
  if (opts.verifierProofs) body.verifier_proofs = proofsToWire(opts.verifierProofs)
  if (opts.clientPubkey && opts.clientSignature) {
    body.client_pubkey = bareHex(opts.clientPubkey)
    body.client_signature = bareHex(opts.clientSignature)
  }

  const url = `${base(opts.nodeUrl)}/v1/committee/sign`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await httpError(res, url, 'committee/sign')
  const d = (await res.json()) as {
    key_slot_id: string
    group_public_key: string
    signature_r: string
    signature_z: string
    message_sha256: string
    epoch?: number
  }
  return {
    keySlotId: d.key_slot_id,
    groupPublicKey: hexToBytes(d.group_public_key),
    signature: {r: hexToBytes(d.signature_r), z: hexToBytes(d.signature_z)},
    messageSha256: hexToBytes(d.message_sha256),
    epoch: Number(d.epoch ?? 0),
  }
}

export interface CommitteeDecryptOpts {
  nodeUrl: string
  committeeToken: CompoundTokenWire
  ciphertext: Ciphertext
  identity: Uint8Array
  decryptingSet: number[]
  blsPeers: BlsPeer[]
  userSignature?: Uint8Array
  ciphertextEpoch?: number
  targetKeykeeper?: string
  verifierProofs?: VerifierProof[]
  /** client request signature (see {@link CommitteeSignOpts}). */
  clientPubkey?: Uint8Array
  clientSignature?: Uint8Array
}

/** Decrypt via committee authorization. The slot id is taken from the token. */
export async function committeeDecrypt(opts: CommitteeDecryptOpts): Promise<Uint8Array> {
  const body: Record<string, unknown> = {
    committee_token: opts.committeeToken,
    ciphertext: ctToWire(opts.ciphertext),
    identity: new TextDecoder().decode(opts.identity),
    decrypting_set: opts.decryptingSet,
    bls_peers: opts.blsPeers.map(p => ({id: p.id, peer_id: p.peerId})),
  }
  if (opts.userSignature) body.user_signature = bareHex(opts.userSignature)
  if (opts.ciphertextEpoch !== undefined) body.ciphertext_epoch = opts.ciphertextEpoch
  if (opts.targetKeykeeper) body.target_keykeeper = strip0x(opts.targetKeykeeper)
  if (opts.verifierProofs) body.verifier_proofs = proofsToWire(opts.verifierProofs)
  if (opts.clientPubkey && opts.clientSignature) {
    body.client_pubkey = bareHex(opts.clientPubkey)
    body.client_signature = bareHex(opts.clientSignature)
  }

  const url = `${base(opts.nodeUrl)}/v1/committee/decrypt`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await httpError(res, url, 'committee/decrypt')
  const d = (await res.json()) as {plaintext: string}
  return base64Decode(d.plaintext)
}

// ─── keeper: POST /v1/shards/ibe/extract (identity-key extraction) ────

/** One node's extraction partial, decoded from the wire. */
export interface IbeExtractionPartial {
  /** The node's BLS group identifier (1..n). */
  identifier: number
  /** 48-byte compressed G1 partial `D_i = sk_i · Q_ID`. */
  value: Uint8Array
  /** The node's 96-byte G2 verifying share (the dual-group reply's first half). */
  verifyingShareG2: Uint8Array
  /** Slot epoch when served. */
  epoch: number
  /** The node that served it (for identifiable-abort reporting). */
  nodeUrl: string
}

export interface IbeExtractOpts {
  /** Base URLs of ≥ k keeper nodes holding the slot's BLS shards. */
  nodeUrls: string[]
  /** MUST be identity-scoped: the keeper enforces `identity_hash == keccak256(identity)`. */
  committeeToken: CompoundTokenWire
  /** The requested IBE identity, in the clear (the node computes Q_ID from it). */
  identity: string
  /** Owner signature over `keccak256("keykeeper:ibe-extract:v1" ‖ identity)` when the
   *  slot has a registered `user_pubkey`. */
  userSignature?: Uint8Array
  ciphertextEpoch?: number
  verifierProofs?: VerifierProof[]
  /** client request signature (see {@link CommitteeSignOpts}). */
  clientPubkey?: Uint8Array
  clientSignature?: Uint8Array
}

async function ibeExtractOne(nodeUrl: string, opts: IbeExtractOpts): Promise<IbeExtractionPartial> {
  const body: Record<string, unknown> = {
    committee_token: opts.committeeToken,
    identity: opts.identity,
  }
  if (opts.userSignature) body.user_signature = bareHex(opts.userSignature)
  if (opts.ciphertextEpoch !== undefined) body.ciphertext_epoch = opts.ciphertextEpoch
  if (opts.verifierProofs) body.verifier_proofs = proofsToWire(opts.verifierProofs)
  if (opts.clientPubkey && opts.clientSignature) {
    body.client_pubkey = bareHex(opts.clientPubkey)
    body.client_signature = bareHex(opts.clientSignature)
  }
  const url = `${base(nodeUrl)}/v1/shards/ibe/extract`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await httpError(res, url, 'shards/ibe/extract')
  const d = (await res.json()) as {
    identifier: number
    extraction_share: string
    verifying_share: string
    epoch: number
  }
  const vs = base64Decode(d.verifying_share)
  return {
    identifier: Number(d.identifier),
    value: base64Decode(d.extraction_share),
    // The reply is the 144-byte dual-group encoding (96B G2 ‖ 48B G1); the IBE pairing
    // check needs the G2 half.
    verifyingShareG2: vs.slice(0, 96),
    epoch: Number(d.epoch),
    nodeUrl,
  }
}

/**
 * Fan out to the keeper nodes and collect extraction partials. Nodes that refuse or are
 * down are skipped; throws — naming every node and its reason — only when NONE served.
 * The caller combines with `ibeCombineDecrypt`/`ibeCombineExtract`, which pairing-verify
 * each partial (identifiable abort names the node via the identifier).
 */
export async function requestIbeExtractionPartials(
  opts: IbeExtractOpts,
): Promise<IbeExtractionPartial[]> {
  if (opts.nodeUrls.length === 0) throw new Error('requestIbeExtractionPartials: no node URLs')
  const settled = await Promise.allSettled(opts.nodeUrls.map(u => ibeExtractOne(u, opts)))
  const partials = settled
    .filter((r): r is PromiseFulfilledResult<IbeExtractionPartial> => r.status === 'fulfilled')
    .map(r => r.value)
  if (partials.length === 0) {
    const why = settled
      .map((r, i) => {
        if (r.status === 'fulfilled') return null
        const e = r.reason as {message?: string}
        return `${opts.nodeUrls[i]}: ${e?.message ?? String(r.reason)}`
      })
      .filter(Boolean)
      .join('; ')
    throw new Error(`requestIbeExtractionPartials: no node served an extraction — ${why}`)
  }
  return partials
}
