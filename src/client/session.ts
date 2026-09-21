// Session — the managed, product-agnostic handle returned by
// `client.openSession(...)`. It holds a slot's assembled master key + the
// current JWT, keeps the JWT fresh (lazy, no timers), re-assembles the key when
// the slot rotates, and exposes encrypt / decrypt / sign bound to the slot.
//
// All crypto/HTTP is delegated to the existing primitives — this layer only
// orchestrates them. No transport/roster/messaging concepts live here.

import {
  encryptEnvelope,
  decryptEnvelope,
  toBytes,
  fromBytes,
  type GroupEnvelope,
} from '../crypto/envelope.js'
import {fetchMpk, fetchAndAssembleKey} from '../keys/node-client.js'
import {redeemRenewalToken, isJwtExpiringSoon} from '../auth/verifier.js'
import {signCustody, type FrostSignResult} from '../signing/frost.js'
import {signEoaDigest, type EoaSignature} from '../signing/ecdsa.js'
import {SlotRotatedError} from '../errors.js'

/** Per-call overrides for a FROST custody signature. */
export interface SignOpts {
  /** Explicit signer set (u16 ids); omit → node uses 1..k. */
  signingSet?: number[]
  /** 64-byte Ed25519 user signature — required iff the slot has an owner key. */
  userSignature?: Uint8Array
  /** 20-byte operator address to pin (anti-Sybil). */
  targetKeykeeper?: string
  /** Idempotency key (required when userSignature is set). */
  requestId?: string
}

/** A live, managed access session for one key slot. */
export interface Session {
  /** 0x-prefixed bytes32 slot id. */
  readonly slotId: string
  /** Subject the JWT was minted for. */
  readonly holder: string
  /** 96-byte compressed G2 group public key of the currently-assembled epoch. */
  readonly mpkBytes: Uint8Array
  /** Epoch of the currently-assembled master key. */
  readonly epoch: number
  /** The current (possibly auto-renewed) JWT. */
  readonly jwt: string

  /** Encrypt to this slot's group key. Local + synchronous (needs no JWT). */
  encrypt(
    plaintext: Uint8Array,
    opts?: {identity?: Uint8Array; epoch?: bigint | null},
  ): Uint8Array
  /** Decrypt with the assembled master key. Refreshes the JWT first and, on an
   *  epoch mismatch (the slot rotated), re-assembles and retries once. */
  decrypt(envelope: Uint8Array | GroupEnvelope): Promise<Uint8Array>
  /** FROST-Ed25519 custody signature over `message`. */
  sign(message: Uint8Array, opts?: SignOpts): Promise<FrostSignResult>
  /** Threshold-ECDSA signature over a 32-byte digest (EVM EOA slots). */
  signDigest(
    digest: Uint8Array,
    opts?: {targetKeykeeper?: string},
  ): Promise<EoaSignature>
  /** Renew the JWT if it is near expiry and re-assemble on rotation. */
  ensureFresh(): Promise<void>
  /** Zeroize the assembled key and drop this session from its client. */
  close(): Promise<void>
}

/** Construction inputs — internal to the client/session pair. */
export interface SessionInit {
  slotId: string
  slotIdBytes: Uint8Array
  nodes: string[]
  verifier: string | undefined
  jwt: string
  holder: string
  /** Long-lived renewal token — the only auth mode that can silently re-mint. */
  renewalToken: string | undefined
  mpkBytes: Uint8Array
  /** Assembled master key, or `null` to assemble lazily on the first decrypt — so a
   *  sign-only session (e.g. a FROST slot, which has no reconstructable key) never
   *  reconstructs one, and encrypt/sign pay no shard-fetch cost. */
  msk: Uint8Array | null
  epoch: number
  identity: Uint8Array
  skewMs: number
  onClose: (session: Session) => void
}

class ManagedSession implements Session {
  readonly #slotId: string
  readonly #slotIdBytes: Uint8Array
  readonly #nodes: string[]
  readonly #verifier: string | undefined
  readonly #holder: string
  readonly #renewalToken: string | undefined
  readonly #identity: Uint8Array
  readonly #skewMs: number
  readonly #onClose: (session: Session) => void
  #jwt: string
  #msk: Uint8Array | null
  #mpkBytes: Uint8Array
  #epoch: number

  constructor(init: SessionInit) {
    this.#slotId = init.slotId
    this.#slotIdBytes = init.slotIdBytes
    this.#nodes = init.nodes
    this.#verifier = init.verifier
    this.#holder = init.holder
    this.#renewalToken = init.renewalToken
    this.#identity = init.identity
    this.#skewMs = init.skewMs
    this.#onClose = init.onClose
    this.#jwt = init.jwt
    this.#msk = init.msk
    this.#mpkBytes = init.mpkBytes
    this.#epoch = init.epoch
  }

  get slotId(): string {
    return this.#slotId
  }
  get holder(): string {
    return this.#holder
  }
  get mpkBytes(): Uint8Array {
    return this.#mpkBytes
  }
  get epoch(): number {
    return this.#epoch
  }
  get jwt(): string {
    return this.#jwt
  }

  encrypt(
    plaintext: Uint8Array,
    opts?: {identity?: Uint8Array; epoch?: bigint | null},
  ): Uint8Array {
    const identity = opts?.identity ?? this.#identity
    const epoch =
      opts?.epoch !== undefined ? opts.epoch : BigInt(this.#epoch)
    return toBytes(
      encryptEnvelope(this.#slotIdBytes, this.#mpkBytes, identity, plaintext, epoch),
    )
  }

  async decrypt(envelope: Uint8Array | GroupEnvelope): Promise<Uint8Array> {
    const env =
      envelope instanceof Uint8Array ? fromBytes(envelope) : envelope
    await this.ensureFresh()
    const msk = await this.#ensureAssembled()
    try {
      return decryptEnvelope(env, msk)
    } catch (err) {
      // Rotation: a v0x02 envelope produced under a different epoch than our
      // assembled key. Re-assemble against the live slot and retry exactly once.
      if (env.epoch !== null && Number(env.epoch) !== this.#epoch) {
        const staleEpoch = this.#epoch
        await this.#reassemble()
        try {
          return decryptEnvelope(env, this.#msk!)
        } catch (retryErr) {
          // Still failing after re-assembling: the epoch mismatch was real but
          // re-keying did not resolve it. Surface it as a rotation error carrying
          // both epochs rather than the opaque AEAD failure.
          throw new SlotRotatedError({
            expected: Number(env.epoch),
            actual: this.#epoch,
            slotId: this.#slotId,
            message:
              `decrypt failed for slot ${this.#slotId.slice(0, 10)}…: envelope is epoch ` +
              `${Number(env.epoch)}, key was epoch ${staleEpoch}, slot is now epoch ${this.#epoch} ` +
              `(${retryErr instanceof Error ? retryErr.message : String(retryErr)})`,
          })
        }
      }
      throw err
    }
  }

  // Lazily Lagrange-assemble the master key from k-of-n shards on the first decrypt.
  // `encrypt` (public key only) and `sign` (JWT only) never call this — so a FROST /
  // sign-only session never fetches shards or reconstructs a key.
  async #ensureAssembled(): Promise<Uint8Array> {
    if (this.#msk === null) {
      this.#msk = await fetchAndAssembleKey({urls: this.#nodes, jwt: this.#jwt}, this.#slotId)
    }
    return this.#msk
  }

  async sign(message: Uint8Array, opts?: SignOpts): Promise<FrostSignResult> {
    await this.ensureFresh()
    return signCustody({
      nodeUrl: this.#nodes[0]!,
      jwt: this.#jwt,
      slotId: this.#slotId,
      message,
      signingSet: opts?.signingSet,
      userSignature: opts?.userSignature,
      targetKeykeeper: opts?.targetKeykeeper,
      requestId: opts?.requestId,
    })
  }

  async signDigest(
    digest: Uint8Array,
    opts?: {targetKeykeeper?: string},
  ): Promise<EoaSignature> {
    await this.ensureFresh()
    return signEoaDigest({
      nodeUrl: this.#nodes[0]!,
      jwt: this.#jwt,
      slotId: this.#slotId,
      digest,
      targetKeykeeper: opts?.targetKeykeeper,
    })
  }

  /**
   * Renew the JWT if it is near expiry and this session can renew silently. Returns whether
   * it actually renewed.
   *
   * ⚠ THE ONE COPY of that policy. It used to be written out in both `ensureFresh` and
   * `#reassemble`; the duplicate in `#reassemble` was unreachable (its only caller runs
   * `ensureFresh` first), so relaxing the skew or the auth-mode condition here would have
   * left a second, diverging copy enforcing the old rule on a path nothing exercises. Both
   * callers now go through this, and calling it twice is a pure no-op — the check is
   * synchronous and costs no I/O once the token is fresh.
   */
  async #renewJwtIfStale(): Promise<boolean> {
    // Hot path: a still-valid JWT costs zero I/O.
    if (!isJwtExpiringSoon(this.#jwt, this.#skewMs)) return false
    // Silent renewal is only possible with a long-lived renewal token. The
    // other auth modes fail loud on the next node call (401/403) → re-open.
    if (!this.#renewalToken || !this.#verifier) return false
    const t = await redeemRenewalToken(this.#verifier, this.#renewalToken)
    this.#jwt = t.token
    return true
  }

  async ensureFresh(): Promise<void> {
    if (!(await this.#renewJwtIfStale())) return
    // A renewal often coincides with a slot rotation (revocation rotates the
    // slot). Pick up a new epoch + key if it changed.
    const {mpkBytes, epoch} = await fetchMpk(this.#nodes[0]!, this.#slotId)
    if (epoch !== this.#epoch) {
      // Re-assemble only if we'd already assembled (a decrypt happened); otherwise the
      // next decrypt assembles fresh against the new epoch.
      if (this.#msk !== null) {
        const fresh = await fetchAndAssembleKey(
          {urls: this.#nodes, jwt: this.#jwt},
          this.#slotId,
        )
        this.#msk.fill(0)
        this.#msk = fresh
      }
      this.#mpkBytes = mpkBytes
      this.#epoch = epoch
    }
  }

  async #reassemble(): Promise<void> {
    // The shard fetch below is AUTHENTICATED, so it must never go out with a token that has
    // aged out. Today its only caller (`decrypt`) has already run `ensureFresh`, which makes
    // this a no-op — but the call stays so the guarantee belongs to this method rather than to
    // its caller's ordering, which nothing enforces.
    await this.#renewJwtIfStale()
    const {mpkBytes, epoch} = await fetchMpk(this.#nodes[0]!, this.#slotId)
    const fresh = await fetchAndAssembleKey(
      {urls: this.#nodes, jwt: this.#jwt},
      this.#slotId,
    )
    this.#msk?.fill(0)
    this.#msk = fresh
    this.#mpkBytes = mpkBytes
    this.#epoch = epoch
  }

  async close(): Promise<void> {
    this.#msk?.fill(0)
    this.#onClose(this)
  }
}

/** Build a managed session from resolved inputs (used by the client). */
export function newSession(init: SessionInit): Session {
  return new ManagedSession(init)
}
