# Handling failures

> The error taxonomy, what is retryable, and how to tell a denial from an outage.

Every error the SDK throws deliberately extends `TasraError`, so you can
branch on the type instead of matching on `err.message`:

```ts
import {
  isAuthDenied, isRetryable, ThresholdNotMetError, SlotRotatedError,
} from 'tasra-sdk'

try {
  const plaintext = await session.decrypt(envelope)
} catch (e) {
  if (isAuthDenied(e)) return reclaimCredential()   // 401/403 — retrying is futile
  if (e instanceof ThresholdNotMetError) {
    // e.reasons carries ONE ENTRY PER NODE — a DNS failure and a cold DKG
    // are distinguishable here, which is the whole point.
    console.warn(`only ${e.got}/${e.need} answered:`, e.reasons)
  }
  if (isRetryable(e)) return backoffAndRetry()
  throw e
}
```

| Class | Carries | `retryable` |
|---|---|---|
| `TasraError` | base for all of the below | — |
| `TasraHttpError` | `status`, `url`, `body` (200 chars) | 5xx / 429 |
| `AuthDeniedError` | as above; 401/403 | **never** |
| `NodeUnreachableError` | `url` — no HTTP answer at all | yes |
| `ThresholdNotMetError` | `got`, `need`, `reasons[]` | yes, unless every node denied |
| `SlotRotatedError` | `expected`, `actual` epoch | yes |
| `CommitteeAuthorizeError` | as `TasraHttpError` — a verifier refused to co-sign | 5xx / 429 |
| `DcqlMalformedError` | the rule is not well-formed OID4VP-DCQL | **never** |
| `VerifierAgentSessionError` | `kind`, `correlation`, `httpStatus?` — a Verifier Agent session failed | `timeout` / `unavailable` only |

`isRetryable(e)` is the coarse signal if you don't want to enumerate types; it
returns `false` for non-SDK errors so a bug in your own code never gets retried.
`isAuthDenied(e)` is keyed on HTTP status rather than class, so it also catches a
403 from `CommitteeAuthorizeError`.

Argument validation (a malformed slot id, a client configured with no nodes) still
throws plain `Error` — those are programming mistakes, not runtime conditions to
branch on.

---

[← Back to the README](../README.md) · [Documentation index](README.md)
