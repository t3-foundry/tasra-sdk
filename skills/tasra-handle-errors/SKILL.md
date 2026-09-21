---
name: tasra-handle-errors
description: Catch, classify and retry errors thrown by tasra-sdk — the TasraError taxonomy, retryable vs never-retry, AuthDeniedError, ThresholdNotMetError with per-node reasons, SlotRotatedError, VerifierAgentSessionError kinds, and the isAuthDenied / isRetryable guards. Use for "how do I handle errors", "401 from node", "threshold not met", "slot rotated", retry and backoff questions.
metadata:
  package: tasra-sdk
  sources:
    - docs/errors.md
    - dist/errors.d.ts
---

# Handling failures

Every error the SDK's network layer throws deliberately extends `TasraError`
and carries a `retryable` flag. Branch on the type or on the two guards; never
on `message`. Pure-crypto helpers (`decryptWithMasterKey`, `ibeDecryptWithKey`,
`combineDecryptShares`, …) throw a plain `Error` on a bad key or ciphertext;
`isRetryable` correctly reports `false` for those. All classes below are
importable from `tasra-sdk`.

```ts
import {isAuthDenied, isRetryable, ThresholdNotMetError, SlotRotatedError, TasraError} from 'tasra-sdk'

try {
  return await session.decrypt(envelope)
} catch (e) {
  if (isAuthDenied(e)) return reclaimCredential()          // 401/403: retrying is futile
  if (e instanceof ThresholdNotMetError) {
    log(`${e.got}/${e.need}`, e.reasons)                   // one reason per node
    if (!e.retryable) return reclaimCredential()           // retryable false ⇒ every node denied the JWT
  }
  // SlotRotatedError is marked retryable, but `Session.decrypt` throws it only AFTER it re-assembled at
  // the slot's live epoch and retried once, so the same envelope takes the identical path: report the
  // epoch mismatch (e.expected is the envelope's, e.actual the slot's) instead of looping on it
  if (e instanceof SlotRotatedError) throw e
  if (isRetryable(e)) return backoffAndRetry()
  throw e                                                   // programming error or non-retryable
}
```

A bounded retry loop: cap the attempts and the delay, jitter the backoff, count
re-claims separately, and rethrow the original error rather than a wrapper.

```ts
async function withRetry<T>(op: () => Promise<T>, reclaim: () => Promise<boolean>): Promise<T> {
  let reclaims = 0
  for (let attempt = 1; ; attempt++) {
    try { return await op() } catch (e) {
      const denied = isAuthDenied(e) || (e instanceof ThresholdNotMetError && !e.retryable)
      if (denied && reclaims++ < 1 && await reclaim()) continue           // a re-claim is not an attempt
      if (e instanceof SlotRotatedError || !isRetryable(e) || attempt >= 4) throw e
      const delay = Math.min(200 * 2 ** (attempt - 1), 5_000)             // double, then cap
      await new Promise(r => setTimeout(r, delay * (0.5 + Math.random() / 2)))   // jitter
    }
  }
}
```

## The taxonomy

| Class | Carries | `retryable` |
|---|---|---|
| `TasraError` | base; `retryable`, optional `cause` | per subclass |
| `TasraHttpError` | `status`, `url`, `body` (≤ 200 chars) | 5xx and 429 |
| `AuthDeniedError` | extends `TasraHttpError`; HTTP 401/403 | never |
| `NodeUnreachableError` | `url`; no HTTP answer at all (DNS, refused, CORS, timeout) | yes |
| `ThresholdNotMetError` | `got`, `need`, `reasons[]` | defaults to yes; the thrower passes `retryable: false` when every node denied |
| `SlotRotatedError` | `expected`, `actual` epoch (both `number`) | yes, but see below |
| `CommitteeAuthorizeError` | extends `TasraHttpError` (positional constructor: `status, message, {url?, body?}`); a verifier refused to co-sign — notably 403 when that verifier was not drawn for this request | 5xx and 429 |
| `DcqlMalformedError` | the rule is not well-formed DCQL | never |
| `VerifierAgentSessionError` | `kind`, `correlation`, `httpStatus?` | only `timeout` and `unavailable` |

`isRetryable(e)` returns `false` for anything that is not a `TasraError`, so
a `TypeError` from your own code is never retried. It returns a plain boolean
and does not narrow the type; `isAuthDenied` narrows to `TasraHttpError`.
Under strict TypeScript, test `e instanceof TasraError` first when you need
the fields. `body` on `TasraHttpError` is truncated to 200 characters by the
network layer, not by you. `isAuthDenied(e)` keys on the
HTTP status, so it also catches a 403 wrapped in `CommitteeAuthorizeError`; it
is `false` for a `ThresholdNotMetError` even when every reason is a 401 — read
`e.retryable` for that case, never the `reasons` strings — and `false` for a
`VerifierAgentSessionError`, which is not an HTTP error at all: a 401 from the
verifier-agent arrives as `kind: 'protocol'` with `httpStatus: 401`.

`SlotRotatedError` is thrown from exactly one place, `Session.decrypt`, and only
after the session re-assembled at the slot's live epoch and retried the envelope
once. Its `retryable: true` therefore overstates the case; treat the epoch
mismatch as a result, not as a transient failure. The raw decrypt paths report a
rotation differently: a `ciphertextEpoch` pinned to a rotated slot answers HTTP
410, which arrives as a non-retryable `TasraHttpError`.

## Constructing errors (tests, simulations)

```ts
new TasraHttpError({status: 503, url, body})            // 5xx/429 → retryable
new AuthDeniedError({status: 403, url, body})               // never retryable
new NodeUnreachableError({url, cause})
new ThresholdNotMetError({got: 1, need: 3, reasons, retryable: false})   // retryable defaults to true
new SlotRotatedError({expected: 4, actual: 5, slotId})      // epochs are numbers; slotId?: string, message only
new VerifierAgentSessionError('timeout', sessionId, 'poll: gave up', httpStatus)   // (kind, correlation, message, httpStatus?)
new CommitteeAuthorizeError(403, 'verifier refused to co-sign', {url, body})    // positional too: (status, message, opts?)
new DcqlMalformedError('rule is not an object')
```

## Reading `ThresholdNotMetError`

`reasons` has one string per node that failed, so a DNS failure on one node and
a cold DKG on another are distinguishable. Fewer than `k` answered; a restarting
node or a DKG that has not finished clears on its own, which is why it defaults
to retryable. The SDK does not inspect `reasons`: when every node denied, the
throwing code path passes `retryable: false` explicitly. So `retryable === false`
here means exactly "every node denied the JWT" — re-claim on it, and log
`reasons` rather than matching on them.

## `VerifierAgentSessionError.kind`

`timeout` (poll gave up, session may still complete), `unavailable` (verifier-agent could
not answer), `refused` (a verifier or the wallet said no), `protocol`
(malformed reply, 401/404), `cancelled` (your `AbortSignal` fired).
`correlation` is the session id and is safe to log.

## Refusals that are not `TasraError`s

Two ordinary outcomes arrive as a **plain `Error`**, so `isRetryable` reports `false`
(correctly) but nothing in the taxonomy names them. Both are decisions, not faults —
handle them where they are thrown rather than in the generic catch:

| thrown by | message | what it means |
|---|---|---|
| `presentToRequestUri` | `no held credential answers: <query id>` | the wallet refused to present: nothing it holds satisfies the slot's rule. Nothing was sent. |
| `presentToRequestUri` | `presentation declined` | your `choose` callback returned `undefined` with candidates available. |

The pure-crypto helpers behave the same way (`decryptWithMasterKey`,
`ibeDecryptWithKey`, `combineDecryptShares` throw a plain `Error` on a bad key or
tampered ciphertext). A committee refusal, by contrast, *is* typed — it reaches you as
`VerifierAgentSessionError` with `kind: 'refused'` when the verifiers decline, so an
out-of-scope identity or an unsatisfied rule at the committee is distinguishable from a
wallet-side refusal by type alone.

## Common mistakes

- ❌ Regexing `err.message`. Wording changes; types and fields do not.
- ❌ Reading every 403 as "my credential is wrong". Some are about the *route*: a
  production-posture keeper answers `legacy JWT eoa-digest cannot satisfy committee-only
  or holder-bound operation authorization` to any bearer-JWT EOA signing request, however
  good the token. No credential fixes it — the call has to move to the committee path
  (`tasra-sign-and-decrypt`).
- ❌ Retrying `AuthDeniedError`. The same credential will be refused again;
  redeem a new one or re-open the session. A 403 from one verifier on the
  committee path is not always about the credential — that verifier may not have
  been drawn, and the gather tolerates it as long as the quorum co-signs.
- ❌ Treating a non-empty `reasons` as fatal. Check whether any node succeeded
  and whether the failures are transient.
- ❌ Catching `Error` and retrying everything. Use `isRetryable`.
- ❌ Treating a wallet refusal as a failure of your code. `no held credential answers`
  is the wallet working correctly; surface it to the holder.

## Where to read more

- What a live run needs (endpoints, slot, credential): `tasra-getting-started`.
- `node_modules/tasra-sdk/dist/errors.d.ts`; `CommitteeAuthorizeError` is declared in
  `dist/committee/client.d.ts` (re-exported from the main entry).
