// Identity-scope matching for (identity-scoped threshold decryption).
//
// ⚠⚠ THIS FILE MUST AGREE WITH THE RUST CRATE EXACTLY — it mirrors
// the reference scope matcher, and the shared corpus
// (test/oid4vp-vectors.json, `scope_matcher` family) pins the two on every run.
//
// A DCQL rule answers WHO may operate; `scopeCovers` answers WHICH identity a caller
// may operate *on*, by testing a scope grant found in a verified credential against the
// requested identity string. The grammar is deliberately minimal — a pattern language
// is an attack surface — and every path fails CLOSED: an oversize or NUL-bearing input
// matches nothing rather than erroring or being coerced.
//
// Grammar (raw-byte, case-sensitive; identities are `/`-segmented UTF-8):
//  - exact:          `g` covers exactly `g`.
//  - segment-prefix: `p/*` covers `p` itself and anything strictly under `p/`. The
//    segment boundary is load-bearing: `patient:12/*` covers `patient:12` and
//    `patient:12/labs` but MUST NOT cover the sibling `patient:123` (the classic
//    prefix-match bug — its own corpus vector).
//  - explicit-open:  bare `"*"` covers everything (visible in the committed rule,
//    never a default).
//
// No mid-path wildcards, no regex. Higher layers (the namespace binding in
// `oid4vp.ts#evaluateIdentityScoped`) decide *whose* grant is honoured; this function
// only decides whether a given grant string reaches a given identity string.

/**
 * Max BYTE length of a scope grant or an identity (the reference implementation's cap). Anything
 * longer fails closed — a grant or identity this large is a bug or an attack, not a
 * real subject path.
 */
export const MAX_IDENTITY_LEN = 1024

const encoder = new TextEncoder()

/**
 * Whether the scope `grant` (from a verified credential) covers the requested
 * `identity`. Fail-closed on oversize or NUL-bearing inputs.
 *
 * ⚠ Implemented over UTF-8 BYTES, not UTF-16 code units, deliberately: the reference implementation
 * compares raw bytes, the length cap is in bytes, and the `/`-boundary check indexes a
 * byte position. Operating on `.length`/`charAt` would diverge for any non-ASCII
 * segment.
 */
export function scopeCovers(grant: string, identity: string): boolean {
  const g = encoder.encode(grant)
  const id = encoder.encode(identity)
  if (g.length > MAX_IDENTITY_LEN || id.length > MAX_IDENTITY_LEN) return false
  if (g.includes(0) || id.includes(0)) return false

  // Explicit-open: the whole namespace, written in the rule on purpose.
  if (grant === '*') return true

  // Segment-prefix: `p/*` covers `p` and anything strictly beneath `p/`. The next byte
  // after the prefix MUST be `/`, so a longer sibling segment (`patient:123` vs
  // `patient:12`) is NOT covered — that boundary check is the whole point.
  // (`/` and `*` are ASCII, so the string-level suffix test equals the byte-level one.)
  if (grant.endsWith('/*')) {
    const prefix = g.subarray(0, g.length - 2)
    if (bytesEqual(id, prefix)) return true
    return id.length > prefix.length && id[prefix.length] === 0x2f && startsWith(id, prefix)
  }

  // Exact match — a grant naming one identity.
  return bytesEqual(g, id)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false
  return true
}
