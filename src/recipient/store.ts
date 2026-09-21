// Recipient-side DCQL access gate — the client half of the platform-blindness
// guarantee. A message RECIPIENT holds their own credentials locally. Given a
// slot's DCQL rule, the recipient can decide LOCALLY whether they satisfy it —
// before, and WITHOUT, contacting the platform. This module is therefore PURE —
// no HTTP, no chain, no I/O.
//
// It reuses the SAME evaluator the nodes and verifier run (src/auth/oid4vp.ts,
// pinned to the reference implementation by the conformance vectors in
// test/oid4vp-vectors.json), so a recipient local verdict is identical to the
// verdict the keepers would reach.

import {evaluate, validate, DcqlMalformedError, jsonCredential, type CredentialView} from '../auth/oid4vp.js'

/**
 * One credential the recipient holds, described as a structured credential view.
 * Build these from your own store of verifiable credentials / verifier JWTs.
 */
export interface HeldCredential {
  /** The credential's format identifier (e.g. `"jwt_vc_json"`). */
  format: string
  /** The credential's type list (for `jwt_vc_json`, its `type` array). */
  types: readonly string[]
  /** The parsed credential body (JSON object with claims). */
  body: unknown
}

/**
 * A recipient's local credential store. Holds structured credentials and
 * evaluates them against OID4VP-DCQL rules. Each credential is individually
 * matched — no aggregation into a single subject.
 *
 * Everything here is in-memory and synchronous: deciding access reveals nothing
 * to the platform.
 */
export class RecipientStore {
  private readonly credentials: CredentialView[]

  constructor(credentials: (HeldCredential | CredentialView)[] = []) {
    this.credentials = credentials.map(c =>
      'claim' in c && typeof c.claim === 'function'
        ? c
        : jsonCredential(c as HeldCredential),
    )
  }

  /** Add a credential (returns `this` for chaining). */
  add(credential: HeldCredential | CredentialView): this {
    this.credentials.push(
      'claim' in credential && typeof credential.claim === 'function'
        ? credential
        : jsonCredential(credential as HeldCredential),
    )
    return this
  }

  /** The credential views held in this store. */
  views(): readonly CredentialView[] {
    return this.credentials
  }

  /**
   * Does this recipient satisfy `rule`? Pure, local, platform-blind.
   *
   * @returns `true` to grant, `false` to deny.
   * @throws {DcqlMalformedError} if the rule itself is broken (a slot-author
   *   bug — the same class the node returns as 400, not a 403 deny). Callers
   *   who want a never-throwing check should use {@link canAccess}.
   */
  satisfies(rule: string): boolean {
    return evaluate(rule, this.credentials)
  }

  /**
   * Build a store from parsed JWT credential bodies.
   * Each entry needs a `type` array and an `iss` field in the body at minimum.
   */
  static fromJwtBodies(
    bodies: Array<{type: string[]; iss: string; [key: string]: unknown}>,
  ): RecipientStore {
    const held: HeldCredential[] = bodies.map(b => ({
      format: 'jwt_vc_json',
      types: b.type,
      body: b,
    }))
    return new RecipientStore(held)
  }
}

/**
 * Convenience: can this recipient access a slot with `rule`? Platform-blind.
 *
 * Accepts a {@link RecipientStore} or a bare {@link HeldCredential} list.
 * Unlike {@link RecipientStore.satisfies}, a MALFORMED rule returns `false`
 * (fail-closed) rather than throwing.
 */
export function canAccess(rule: string, store: RecipientStore | HeldCredential[]): boolean {
  const s = Array.isArray(store) ? new RecipientStore(store) : store
  try {
    return s.satisfies(rule)
  } catch (e) {
    if (e instanceof DcqlMalformedError) return false
    throw e
  }
}

/**
 * Explicitly validate a slot's rule client-side: returns normally if well-formed,
 * throws {@link DcqlMalformedError} otherwise.
 */
export function validateRule(rule: string): void {
  validate(rule)
}
