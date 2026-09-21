// High-level committee-authorization orchestration.
//
// The low-level pieces already exist: `gatherCommitteeToken` (fan out + assemble) and
// `committeeSign`/`committeeDecrypt` (submit) in ./client.ts, the committee math in ./token.ts,
// and the chain reads in ../chain/client.ts. This module is the glue that turns them into a
// one-call flow: read the per-request randomness + the slot's verifier-committee policy from
// chain, gather a quorum of attributable verifier signatures, assemble the compound token, and
// — when the full verifier set is known and an anchored snapshot matches — build the trustless
// verifier-set inclusion proofs the keeper checks against `VerifierSetRegistry`.
//
// The chain reads are injected (`CommitteeChainReads`) so this works with the SDK chain client
// or raw viem. Proofs are OPTIONAL: when the verifier directory lacks operator/pubkey or no
// snapshot is anchored, the token is submitted without proofs and the keeper falls back to its
// configured verifier set.

import {
  gatherCommitteeToken,
  committeeSign,
  committeeDecrypt,
  requestIbeExtractionPartials,
  type VerifierProof,
  type CommitteeSignOpts,
  type CommitteeDecryptOpts,
} from './client.js'
import {ibeCombineDecrypt, ibeCombineExtract, type IbeCiphertext} from '../crypto/ibe.js'
import {
  merkleRoot,
  merkleProof,
  verifierLeaf,
  clientBindingHash,
  compoundTokenHash,
  decodeCompoundToken,
  type TokenType,
  type CompoundTokenWire,
} from './token.js'
import {hexToBytes, bytesToHex} from '../crypto/hex.js'
import {ed25519} from '@noble/curves/ed25519'
import {createHolderProof, type HolderSigner} from '../auth/holderProof.js'
import type {FrostSignResult} from '../signing/frost.js'

/**
 * client request signature. The client (== the credential holder) proves it authorized
 * this exact request by signing `clientBindingHash(slotId, tokenHash)`. Supply an ed25519 signer
 * (the holder's authentication key) — the keeper (hot path) and the accountant (audit) verify it.
 */
export interface ClientSigner {
  /** 32-byte ed25519 public key. */
  publicKey: Uint8Array
  /** Sign the 32-byte client-binding hash → 64-byte ed25519 signature. */
  sign(bindingHash: Uint8Array): Uint8Array | Promise<Uint8Array>
}

/**
 * A holder proof minted PER VERIFIER — see {@link holderProofPerVerifier}.
 *
 * ⚠ A single proof cannot serve a committee: it is bound to a nonce that lives in ONE
 * verifier's store, consumed atomically, so the first verifier to answer spends it and the
 * rest refuse (401) under `require_holder_binding`. Pass a function instead of a string and
 * the gather asks each candidate verifier for its own nonce.
 */
export type HolderProofPerVerifier = (verifier: CommitteeVerifier) => Promise<string> | string

/**
 * One holder proof-of-possession per drawn verifier: fetch THAT verifier's nonce, sign it
 * with the holder key over the same credentials + slot, hand it back for that verifier only.
 * Pass the result as `holderProof` to {@link requestCommitteeToken} (or the one-call
 * helpers built on it).
 */
export function holderProofPerVerifier(opts: {
  signer: HolderSigner
  /** The verifiers' expected audience (their token `iss`). */
  audience: string
  credentials: string[]
  slotId?: string
  action?: string
  ttlSecs?: number
}): HolderProofPerVerifier {
  return verifier =>
    createHolderProof(verifier.url, {
      signer: opts.signer,
      audience: opts.audience,
      credentials: opts.credentials,
      slotId: opts.slotId,
      action: opts.action,
      ttlSecs: opts.ttlSecs,
    })
}

/** A {@link ClientSigner} from a 32-byte ed25519 secret key (the common `did:key` holder). */
export function ed25519ClientSigner(secretKey: Uint8Array): ClientSigner {
  return {
    publicKey: ed25519.getPublicKey(secretKey),
    sign: (bindingHash: Uint8Array) => ed25519.sign(bindingHash, secretKey),
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

function toBytes32(x: `0x${string}` | Uint8Array): Uint8Array {
  return typeof x === 'string' ? hexToBytes(x) : x
}

/** One member of the active verifier set. `operator`+`pubkey` are needed only to build the
 *  trustless snapshot proofs; `index`+`url` alone suffice for the keeper's configured-set path. */
export interface CommitteeVerifier {
  index: number
  /** Verifier HTTP base URL. */
  url: string
  /** 20-byte operator address (hex). */
  operator?: string
  /** 32-byte ed25519 signing pubkey (hex). */
  pubkey?: string
}

/** The chain reads the committee flow needs. Adapt from the SDK chain client with
 *  {@link committeeChainReadsFromClient}, or supply raw viem reads. */
export interface CommitteeChainReads {
  /** 32-byte beacon seed for the current epoch. */
  seed(): Promise<`0x${string}` | Uint8Array>
  /** Current beacon epoch. */
  epoch(): Promise<bigint | number>
  /** Seed of a past epoch (`ThresholdRandomBeacon.seedAt`) — needed for `epochLag > 0`. */
  seedAt?(epoch: bigint): Promise<`0x${string}` | Uint8Array>
  /** The slot's `[committee, quorum]` verifier policy (both `uint16`). */
  verifierPolicy(slotId: `0x${string}`): Promise<readonly [number, number]>
  /** Optional anchored verifier-set snapshot `{root, size}` at an epoch — enables trustless
   *  proofs. Return `null` when none is anchored. */
  snapshot?(epoch: bigint): Promise<{root: `0x${string}` | Uint8Array; size: number} | null>
}

/** Adapt the SDK chain client's `readers` into {@link CommitteeChainReads}. */
export function committeeChainReadsFromClient(readers: {
  beacon: {seed(): Promise<unknown>; epoch(): Promise<unknown>; seedAt?(epoch: bigint): Promise<unknown>}
  keyRegistry: {verifierPolicy(id: `0x${string}`): Promise<readonly [number, number]>}
  verifierSet?: {snapshotAt(epoch: bigint): Promise<unknown>}
}): CommitteeChainReads {
  return {
    seed: () => readers.beacon.seed() as Promise<`0x${string}`>,
    epoch: () => readers.beacon.epoch() as Promise<bigint>,
    ...(readers.beacon.seedAt ? {seedAt: (epoch: bigint) => readers.beacon.seedAt!(epoch) as Promise<`0x${string}`>} : {}),
    verifierPolicy: id => readers.keyRegistry.verifierPolicy(id),
    ...(readers.verifierSet
      ? {
          snapshot: async (epoch: bigint) => {
            const s = (await readers.verifierSet!.snapshotAt(epoch)) as
              | {root: `0x${string}`; size: number | bigint}
              | readonly [`0x${string}`, number | bigint]
            const root = Array.isArray(s) ? s[0] : (s as {root: `0x${string}`}).root
            const size = Number(Array.isArray(s) ? s[1] : (s as {size: number | bigint}).size)
            const zero = /^0x0{64}$/i.test(root as string)
            return size > 0 && !zero ? {root: root as `0x${string}`, size} : null
          },
        }
      : {}),
  }
}

export interface RequestCommitteeTokenOpts {
  chain: CommitteeChainReads
  /** Pin the draw to `latest - epochLag` (0 or 1). 1 = the previous epoch, always anchored: no wait for the accountants. */
  epochLag?: number
  /** The active verifier set (index→url; add operator+pubkey to enable trustless proofs).
   *  Asking the whole set is fine — non-drawn verifiers reply 403 and are skipped. */
  verifiers: CommitteeVerifier[]
  /** 0x-prefixed 32-byte slot id. */
  slotId: string
  /** Holder DID (the credentials' subject). */
  holder: string
  /** Compact-JWS verifiable credentials. */
  credentials: string[]
  /**
   * Holder proof-of-possession. Required by default — it is what stops a stolen
   * credential being replayed by someone who did not earn it.
   *
   * ⚠ Optional only because the SERVER makes it optional: `holder_proof` is an
   * `Option` and a verifier with `require_holder_binding = false` accepts the
   * request without one. A client that refuses what the server accepts is the
   * same defect as one that demands a field the server ignores — it makes a
   * valid deployment unreachable. The opt-out is explicit so it cannot happen by
   * forgetting to pass a value.
   */
  holderProof?: string | HolderProofPerVerifier
  /** Send no holder proof. Only valid against `require_holder_binding = false`. */
  allowNoHolderProof?: boolean
  /** Token type — default `'JWT'`. */
  tokenType?: TokenType
  /** Token TTL in seconds — default 300. */
  ttlSecs?: number
  /** Override "now" (unix seconds), mainly for tests. */
  nowSecs?: number
  /** sign the request bundle with the holder's key so the keeper + audit can verify
   *  the user authorized this operation. Omit to skip (keeper accepts unless it requires it). */
  clientSigner?: ClientSigner
  /**
   * The requested IBE identity, for an identity-scoped operation ONLY (maps
   * to the wire field `identity`). The committee evaluates the slot's scope binding
   * against it and the token carries `identity_hash = keccak256(identity)` — a quorum
   * attests THIS identity, keepers refuse the token on every identity-blind endpoint,
   * and the extraction endpoint enforces the hash binding. Omit for sign/decrypt.
   *
   * ⚠ Named `scopedIdentity`, deliberately: `CommitteeDecryptRequestOpts.identity` is
   * the KEM's SENDER identity (AEAD associated data) — an unrelated concept that must
   * never be confused with the WHICH-gate binding.
   */
  scopedIdentity?: string
}

export interface CommitteeTokenResult {
  token: CompoundTokenWire
  committee: number
  quorum: number
  registrySize: number
  seed: Uint8Array
  epoch: number
  /** Trustless snapshot-inclusion proofs for the token's signers, when derivable; else
   *  `undefined` (the keeper then uses its configured verifier set). */
  verifierProofs?: VerifierProof[]
  /** client request signature, when a `clientSigner` was supplied. */
  clientPubkey?: Uint8Array
  clientSignature?: Uint8Array
  /**
   * The slot's `ruleVersion` the committee evaluated against, as
   * reported by the verifiers. `undefined` from a verifier predating it.
   *
   * ⚠ Diagnostic, not a gate — the keeper binds `ruleHash` to its own rule hash,
   * so a token minted under a superseded policy is refused there
   * regardless. What this buys is being able to SAY that is what happened,
   * rather than leaving a refusal indistinguishable from an unauthorized one.
   */
  ruleVersion?: number
}

/**
 * Build snapshot-inclusion proofs for the token's `signerIndexes` from the full ordered verifier
 * directory. Returns `undefined` (never a wrong proof) when the directory is incomplete, a key is
 * missing, or the reconstructed root disagrees with the anchored `snapshotRoot` — so a mismatch
 * degrades to the keeper's configured-set path rather than shipping a proof the keeper rejects.
 */
export function buildVerifierProofs(
  verifiers: CommitteeVerifier[],
  registrySize: number,
  signerIndexes: number[],
  snapshotRoot?: Uint8Array,
): VerifierProof[] | undefined {
  const byIndex = new Map(verifiers.map(v => [v.index, v]))
  const leaves: Uint8Array[] = []
  for (let i = 0; i < registrySize; i++) {
    const v = byIndex.get(i)
    if (!v || !v.operator || !v.pubkey) return undefined
    leaves.push(verifierLeaf(i, hexToBytes(v.operator), hexToBytes(v.pubkey)))
  }
  const root = merkleRoot(leaves)
  if (!root) return undefined
  if (snapshotRoot && !bytesEqual(root, snapshotRoot)) return undefined

  const proofs: VerifierProof[] = []
  for (const idx of signerIndexes) {
    const v = byIndex.get(idx)
    const p = merkleProof(leaves, idx)
    if (!v || !v.operator || !v.pubkey || !p) return undefined
    proofs.push({verifierIndex: idx, operator: v.operator, pubkey: v.pubkey, proof: p.map(bytesToHex)})
  }
  return proofs
}

/**
 * Resolve the per-request randomness + the slot's committee policy from chain, fan out to the
 * drawn verifiers to gather a quorum of attributable signatures, and assemble the compound token
 * (+ trustless verifier proofs when derivable). Throws if the slot has no verifierPolicy or a
 * quorum can't be gathered.
 */
/**
 * Which beacon epoch a draw is pinned to. Keepers and verifiers admit `{latest, latest - 1}`
 * (the seed pin). The accountants anchor an epoch's verifier-set snapshot one settle
 * tick after the epoch starts, so a token pinned to `latest` right after a flip is refused by
 * the keeper ("no verifier-set snapshot anchored at epoch N") until then; `epochLag: 1` pins
 * the draw to the previous epoch, which is always anchored — no wait, same security bound.
 */
export async function pinnedDraw(chain: Pick<CommitteeChainReads, 'seed' | 'seedAt'>, latest: number, epochLag = 0): Promise<{epoch: number; seed: Uint8Array}> {
  const lag = Math.max(0, Math.min(1, Math.floor(epochLag)))
  const epoch = Math.max(0, latest - lag)
  if (epoch === latest) return {epoch, seed: toBytes32(await chain.seed())}
  if (!chain.seedAt) throw new Error('epochLag needs chain.seedAt (ThresholdRandomBeacon.seedAt); adapt the chain reads with committeeChainReadsFromClient')
  return {epoch, seed: toBytes32(await chain.seedAt(BigInt(epoch)))}
}

export async function requestCommitteeToken(opts: RequestCommitteeTokenOpts): Promise<CommitteeTokenResult> {
  const slotId = opts.slotId as `0x${string}`
  if (!opts.holderProof && !opts.allowNoHolderProof) {
    throw new Error(
      'requestCommitteeToken: holderProof is required to prove control of the holder DID. ' +
        'A verifier with `require_holder_binding = false` will accept the request without one — ' +
        'pass `allowNoHolderProof: true` to say so deliberately.',
    )
  }
  const [epochRaw, policy] = await Promise.all([opts.chain.epoch(), opts.chain.verifierPolicy(slotId)])
  const {epoch, seed} = await pinnedDraw(opts.chain, Number(epochRaw), opts.epochLag)
  const committee = Number(policy[0])
  const quorum = Number(policy[1])
  if (committee === 0) {
    throw new Error(`slot ${slotId.slice(0, 10)}… has no verifierPolicy (committee path not wired); use the JWT path`)
  }

  // Registry size (the committee-draw modulus): the anchored snapshot's size when available —
  // it's the value the verifier/keeper agree on — else the directory length.
  let registrySize = opts.verifiers.length
  let snapshotRoot: Uint8Array | undefined
  if (opts.chain.snapshot) {
    const snap = await opts.chain.snapshot(BigInt(epoch)).catch(() => null)
    if (snap && snap.size > 0) {
      registrySize = snap.size
      snapshotRoot = toBytes32(snap.root)
    }
  }
  if (registrySize < committee) {
    throw new Error(`active verifier set (${registrySize}) is smaller than the committee size (${committee})`)
  }

  const now = opts.nowSecs ?? Math.floor(Date.now() / 1000)
  const iat = now - 5
  const exp = now + (opts.ttlSecs ?? 300)

  // Taken from the REFERENCE reply — the one whose ruleHash built the
  // token — so the version and the hash describe one evaluation. Verifiers that
  // straddle an activation legitimately disagree, and pairing a version from one
  // with a hash from another would describe a state that never existed.
  let ruleVersion: number | undefined
  // A per-verifier proof function is resolved inside the gather, against each verifier's
  // own URL; a string is the legacy single proof (fine when holder binding is off).
  const byIndex = new Map(opts.verifiers.map(v => [v.index, v]))
  const holderProofFor =
    typeof opts.holderProof === 'function'
      ? (v: {index: number; url: string}) => (opts.holderProof as HolderProofPerVerifier)(byIndex.get(v.index) ?? {index: v.index, url: v.url})
      : undefined
  const token = await gatherCommitteeToken({
    verifiers: opts.verifiers.map(v => ({index: v.index, url: v.url})),
    quorum,
    holderProofFor,
    onReplies: (_all, reference) => {
      ruleVersion = reference.ruleVersion
    },
    authorize: {
      holder: opts.holder,
      credentials: opts.credentials,
      holderProof: typeof opts.holderProof === 'string' ? opts.holderProof : '',
      tokenType: opts.tokenType ?? 'JWT',
      seed,
      epoch,
      slotId: hexToBytes(slotId),
      registrySize,
      committee,
      iat,
      exp,
      ...(opts.scopedIdentity !== undefined ? {identity: opts.scopedIdentity} : {}),
    },
  })

  const signerIndexes = token.signatures.map(s => s.verifier_index)
  const verifierProofs = buildVerifierProofs(opts.verifiers, registrySize, signerIndexes, snapshotRoot)

  // Sign the request bundle (bound to the token's canonical hash + the slot).
  let clientPubkey: Uint8Array | undefined
  let clientSignature: Uint8Array | undefined
  if (opts.clientSigner) {
    const tokenHash = compoundTokenHash(decodeCompoundToken(token))
    const binding = clientBindingHash(hexToBytes(slotId), tokenHash)
    clientSignature = await opts.clientSigner.sign(binding)
    clientPubkey = opts.clientSigner.publicKey
  }

  return {token, committee, quorum, registrySize, seed, epoch, verifierProofs, clientPubkey, clientSignature, ruleVersion}
}

/** Operation-specific fields for {@link committeeSignRequest} (everything `committeeSign` needs
 *  except the token, which this resolves). */
export interface CommitteeSignRequestOpts extends RequestCommitteeTokenOpts {
  nodeUrl: string
  message: Uint8Array
  signingSet?: number[]
  userSignature?: Uint8Array
  /** The keeper this request targets (anti-Sybil). Defaults to letting the node accept it. */
  targetKeykeeper?: string
}

/** One-call committee-authorized threshold sign: resolve token (+proofs) then POST to the keeper. */
export async function committeeSignRequest(opts: CommitteeSignRequestOpts): Promise<FrostSignResult> {
  const {token, verifierProofs, clientPubkey, clientSignature} = await requestCommitteeToken(opts)
  const signOpts: CommitteeSignOpts = {
    nodeUrl: opts.nodeUrl,
    committeeToken: token,
    message: opts.message,
    signingSet: opts.signingSet,
    userSignature: opts.userSignature,
    targetKeykeeper: opts.targetKeykeeper,
    verifierProofs,
    clientPubkey,
    clientSignature,
  }
  return committeeSign(signOpts)
}

/** Operation-specific fields for {@link committeeDecryptRequest}. */
export interface CommitteeDecryptRequestOpts extends RequestCommitteeTokenOpts {
  nodeUrl: string
  ciphertext: CommitteeDecryptOpts['ciphertext']
  identity: Uint8Array
  decryptingSet: number[]
  blsPeers: CommitteeDecryptOpts['blsPeers']
  userSignature?: Uint8Array
  ciphertextEpoch?: number
  targetKeykeeper?: string
}

/** One-call committee-authorized threshold decrypt. */
export async function committeeDecryptRequest(opts: CommitteeDecryptRequestOpts): Promise<Uint8Array> {
  const {token, verifierProofs, clientPubkey, clientSignature} = await requestCommitteeToken(opts)
  const decOpts: CommitteeDecryptOpts = {
    nodeUrl: opts.nodeUrl,
    committeeToken: token,
    ciphertext: opts.ciphertext,
    identity: opts.identity,
    decryptingSet: opts.decryptingSet,
    blsPeers: opts.blsPeers,
    userSignature: opts.userSignature,
    ciphertextEpoch: opts.ciphertextEpoch,
    targetKeykeeper: opts.targetKeykeeper,
    verifierProofs,
    clientPubkey,
    clientSignature,
  }
  return committeeDecrypt(decOpts)
}

// ─── identity-key extraction (one-call) ────────────────────────────

/** Operation-specific fields for {@link ibeDecryptRequest} / {@link ibeExtractRequest}. */
export interface IbeExtractRequestOpts extends RequestCommitteeTokenOpts {
  /** Base URLs of ≥ k keeper nodes holding the slot's BLS shards. */
  nodeUrls: string[]
  /** The IBE identity to extract for — becomes the token's `scopedIdentity`, so a quorum
   *  attests exactly this identity and the keepers enforce the hash binding. */
  identity: string
  /** Owner signature over the identity-bound extract marker, when the slot has one. */
  userSignature?: Uint8Array
  ciphertextEpoch?: number
}

/**
 * Resolve an identity-scoped committee token, fan out for extraction partials, verify
 * each (identifiable abort — the error names the node), and return `sk_ID` (48-byte
 * compressed G1).
 *
 * ⚠ CUSTODY OPT-IN: holding `sk_ID` is a durable capability over every past and future
 * ciphertext to this identity. Prefer {@link ibeDecryptRequest}, which combines,
 * decrypts and drops it. Zeroize the returned bytes when done.
 */
export async function ibeExtractRequest(opts: IbeExtractRequestOpts): Promise<Uint8Array> {
  const {partials, identityBytes} = await gatherIbePartials(opts)
  const vsMap = new Map(partials.map(p => [p.identifier, p.verifyingShareG2]))
  return ibeCombineExtract(
    vsMap,
    partials.map(p => ({identifier: p.identifier, value: p.value})),
    identityBytes,
  )
}

/**
 * One-call identity-scoped decrypt (the read path): token → extraction fan-out
 * → verify each partial → combine → decrypt. The intermediate `sk_ID` never surfaces.
 */
export async function ibeDecryptRequest(
  opts: IbeExtractRequestOpts & {ciphertext: IbeCiphertext},
): Promise<Uint8Array> {
  const {partials, identityBytes} = await gatherIbePartials(opts)
  const vsMap = new Map(partials.map(p => [p.identifier, p.verifyingShareG2]))
  return ibeCombineDecrypt(
    vsMap,
    partials.map(p => ({identifier: p.identifier, value: p.value})),
    opts.ciphertext,
    identityBytes,
  )
}

async function gatherIbePartials(opts: IbeExtractRequestOpts) {
  const {token, verifierProofs, clientPubkey, clientSignature} = await requestCommitteeToken({
    ...opts,
    scopedIdentity: opts.identity,
  })
  const partials = await requestIbeExtractionPartials({
    nodeUrls: opts.nodeUrls,
    committeeToken: token,
    identity: opts.identity,
    userSignature: opts.userSignature,
    ciphertextEpoch: opts.ciphertextEpoch,
    verifierProofs,
    clientPubkey,
    clientSignature,
  })
  return {partials, identityBytes: new TextEncoder().encode(opts.identity)}
}
