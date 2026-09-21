// Error taxonomy.
//
// Before this existed the SDK threw bare `Error` from ~90 sites, so the only way
// to tell "the JWT was denied" from "the node is unreachable" from "not enough
// nodes answered" was to regex `err.message`. The SDK was doing that to itself in
// node-client.ts. Message-matching breaks on any wording change, and it cannot
// carry structure — a caller that wants the HTTP status, or the per-node reasons
// behind a failed assembly, had nowhere to read them from.
//
// Every class here extends `Error`, so existing `catch (e) { e.message }` code is
// unaffected; the messages keep their previous shape too. What's new is that you
// can branch on the type and read fields off it:
//
//   try {
//     await session.decrypt(envelope)
//   } catch (e) {
//     if (e instanceof AuthDeniedError) return reclaimCredential()   // never retry
//     if (e instanceof ThresholdNotMetError) {
//       console.warn(`only ${e.got}/${e.need} nodes answered:`, e.reasons)
//       return retryLater()                                          // transient
//     }
//     throw e
//   }
//
// `retryable` is the coarse signal for callers that don't want to enumerate
// types: false means the request will fail identically on retry (a denied or
// expired credential, a malformed rule), true means it might not.

/**
 * Base class for every error this SDK throws deliberately. Catch this to
 * distinguish SDK failures from programming errors (`TypeError`, etc.).
 */
export class TasraError extends Error {
  /** `false` when retrying the identical request cannot succeed. */
  readonly retryable: boolean

  constructor(message: string, opts?: {retryable?: boolean; cause?: unknown}) {
    super(message, opts?.cause !== undefined ? {cause: opts.cause} : undefined)
    this.name = new.target.name
    this.retryable = opts?.retryable ?? false
  }
}

/**
 * A node or verifier answered with a non-2xx status. `body` is the response body,
 * truncated to 200 characters — enough to carry the service's own error text
 * without dumping a page of HTML into a log line.
 *
 * 5xx and 429 are marked retryable; other 4xx are not.
 */
export class TasraHttpError extends TasraError {
  readonly status: number
  readonly url: string
  readonly body: string

  constructor(args: {status: number; url: string; body?: string; message?: string; retryable?: boolean}) {
    const body = args.body ?? ''
    super(args.message ?? `${args.url} → HTTP ${args.status}${body ? `: ${body}` : ''}`, {
      retryable: args.retryable ?? (args.status >= 500 || args.status === 429),
    })
    this.status = args.status
    this.url = args.url
    this.body = body
  }
}

/**
 * The credential was rejected: 401 or 403. Never retryable — the same token will
 * be refused again. Re-claim (redeem a fresh credential or renewal) instead.
 */
export class AuthDeniedError extends TasraHttpError {
  constructor(args: {status: number; url: string; body?: string; message?: string}) {
    super({...args, retryable: false})
  }
}

/**
 * The request never got an HTTP answer — DNS failure, connection refused,
 * timeout, CORS. Retryable: the service may simply not be up yet.
 */
export class NodeUnreachableError extends TasraError {
  readonly url: string

  constructor(args: {url: string; message?: string; cause?: unknown}) {
    super(args.message ?? `${args.url} is unreachable`, {retryable: true, cause: args.cause})
    this.url = args.url
  }
}

/**
 * Fewer than the required number of participants answered — too few shards to
 * assemble a key, too few verifier signatures for a quorum, too few nodes for a
 * signing set.
 *
 * `reasons` carries one entry per participant that failed, which is what makes
 * this actionable: previously those were collected and then discarded, so a DNS
 * failure and a cold DKG produced the same opaque message.
 */
export class ThresholdNotMetError extends TasraError {
  /** How many participants answered successfully. */
  readonly got: number
  /** How many were needed. */
  readonly need: number
  /** Why each failing participant failed, one string per participant. */
  readonly reasons: readonly string[]

  constructor(args: {got: number; need: number; reasons?: readonly string[]; message?: string; retryable?: boolean}) {
    const reasons = args.reasons ?? []
    super(
      args.message ??
        `threshold not met: ${args.got}/${args.need} participants answered` +
          (reasons.length ? ` — ${reasons.join('; ')}` : ''),
      // Transient by default: a cold DKG or a restarting node clears on its own.
      // Callers that know better (all-auth failures) pass retryable: false.
      {retryable: args.retryable ?? true},
    )
    this.got = args.got
    this.need = args.need
    this.reasons = reasons
  }
}

/**
 * The slot was re-keyed (rotated) since the key in hand was assembled, so that
 * key cannot read anything encrypted after the rotation. Retryable: re-assemble
 * at the new epoch and try again — the managed {@link Session} does this for you.
 */
export class SlotRotatedError extends TasraError {
  /** The epoch the caller's key/envelope belongs to. */
  readonly expected: number
  /** The slot's current on-chain/served epoch. */
  readonly actual: number

  constructor(args: {expected: number; actual: number; slotId?: string; message?: string}) {
    super(
      args.message ??
        `slot${args.slotId ? ` ${args.slotId.slice(0, 10)}…` : ''} rotated: ` +
          `key is epoch ${args.expected}, slot is now epoch ${args.actual}`,
      {retryable: true},
    )
    this.expected = args.expected
    this.actual = args.actual
  }
}

/**
 * Build the right error for a non-2xx `Response`: {@link AuthDeniedError} for
 * 401/403, otherwise {@link TasraHttpError}. Reads and truncates the body.
 *
 * `label` prefixes the message so it names the operation rather than just the
 * URL (`'committee/sign'` → `committee/sign → HTTP 403: …`).
 */
export async function httpError(
  res: Response,
  url: string,
  label?: string,
): Promise<TasraHttpError> {
  const body = (await res.text().catch(() => '')).slice(0, 200)
  const message = `${label ?? url} → HTTP ${res.status}${body ? `: ${body}` : ''}`
  const args = {status: res.status, url, body, message}
  return res.status === 401 || res.status === 403
    ? new AuthDeniedError(args)
    : new TasraHttpError(args)
}

/**
 * True when `e` is an auth rejection — i.e. retrying is pointless, re-claim
 * instead. Keyed on the HTTP status rather than the class, so it also catches
 * subclasses that carry their own name (e.g. `CommitteeAuthorizeError`).
 */
export function isAuthDenied(e: unknown): e is TasraHttpError {
  return e instanceof TasraHttpError && (e.status === 401 || e.status === 403)
}

/**
 * True when retrying the identical request could plausibly succeed. Non-SDK
 * errors (a `TypeError` from a bug) report `false`.
 */
export function isRetryable(e: unknown): boolean {
  return e instanceof TasraError && e.retryable
}
