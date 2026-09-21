// OID4VP-DCQL conformance harness.
//
// Runs every row of oid4vp-vectors.json — 30 evaluation vectors and 6 commitment
// vectors — through the TypeScript implementation and asserts the verdict.
//
// Two implementations gate the same slots: keepers and accountants run the reference
// evaluator, recipients and this SDK run src/auth/oid4vp.ts. Nothing links them at
// build time, so a corpus neither side authored alone is the only thing that can catch
// a divergence.
//
// The commitment rows carry expected hashes computed by the reference implementation,
// which makes them a known-answer test rather than a round-trip: this file cannot
// satisfy them by being self-consistent, only by being right. That distinction is the
// whole point — a suite that feeds its own values through its own functions passes
// whenever both halves agree, including when both are wrong.
//
// Exits non-zero on any mismatch.

import {readFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {type Hex} from 'viem'
import {
  validate,
  evaluate,
  evaluateIdentityScoped,
  canonicalize,
  jsonCredential,
  DcqlMalformedError,
  type CredentialView,
} from '../src/auth/oid4vp.ts'
// The SHIPPED matcher — the corpus's scope_matcher family pins it directly, since it is
// a public export the recipient-side WHICH gate calls.
import {scopeCovers} from '../src/auth/identityScope.ts'
// ⚠ The SHIPPED commitment function, deliberately — not a local reimplementation of it.
// Recomputing `keccak256(DOMAIN ‖ salt ‖ canon)` here would pin a copy of the algorithm
// and leave the function callers actually use unpinned, which is the same
// "agrees only with itself" failure this corpus exists to prevent.
import {ruleCommitment} from '../src/chain/write.ts'

interface EvalVector {
  name: string
  rule: string
  credentials: {format: string; types: string[]; body: unknown}[]
  expect: 'grant' | 'deny' | 'malformed'
}

interface CommitVector {
  name: string
  rule: string
  salt: Hex
  canonical: string
  commitment: Hex
}

// The identity-scope vector families.
interface ScopeVector {
  name: string
  grant: string
  identity: string
  covers: boolean
}

interface IdentityScopedVector {
  name: string
  rule: string
  credentials: {format: string; types: string[]; body: unknown}[]
  identity: string
  expect: 'grant' | 'deny' | 'malformed'
}

const here = dirname(fileURLToPath(import.meta.url))
const localPath = join(here, 'oid4vp-vectors.json')
const localRaw = readFileSync(localPath, 'utf8')
const corpus = JSON.parse(localRaw) as {
  evaluation: EvalVector[]
  scope_matcher: ScopeVector[]
  identity_scoped: IdentityScopedVector[]
  commitment: CommitVector[]
}

// test/oid4vp-vectors.json is vendored: it is the reference this suite runs against.
// Refreshing it is a manual step (see CONTRIBUTING.md) — nothing here detects a
// change made on the producing side.

let passed = 0
const failures: string[] = []

const views = (v: {credentials: EvalVector['credentials']}): CredentialView[] =>
  v.credentials.map(c => jsonCredential(c))

// ─── evaluation vectors ──────────────────────────────────────────────────────

for (const v of corpus.evaluation) {
  try {
    if (v.expect === 'malformed') {
      // BOTH entry points must refuse. evaluate() calls validate() first, but asserting
      // only validate() would let an evaluate() that swallowed the error pass.
      let validateThrew = false
      try {
        validate(v.rule)
      } catch (e) {
        validateThrew = e instanceof DcqlMalformedError
      }
      let evaluateThrew = false
      try {
        evaluate(v.rule, views(v))
      } catch (e) {
        evaluateThrew = e instanceof DcqlMalformedError
      }
      if (validateThrew && evaluateThrew) passed++
      else
        failures.push(
          `eval/${v.name}: expected malformed ` +
            `(validate threw=${validateThrew}, evaluate threw=${evaluateThrew})`,
        )
    } else {
      validate(v.rule)
      const actual = evaluate(v.rule, views(v)) ? 'grant' : 'deny'
      if (actual === v.expect) passed++
      else failures.push(`eval/${v.name}: expected ${v.expect}, got ${actual}`)
    }
  } catch (e) {
    failures.push(`eval/${v.name}: unexpected error ${e instanceof Error ? e.message : String(e)}`)
  }
}

// ─── scope-matcher vectors (raw scopeCovers pins) ──────────────────

for (const v of corpus.scope_matcher) {
  const got = scopeCovers(v.grant, v.identity)
  if (got === v.covers) passed++
  else failures.push(`scope/${v.name}: expected covers=${v.covers}, got ${got}`)
}

// ─── identity-scoped vectors ──────────────────────────────────────

for (const v of corpus.identity_scoped) {
  try {
    if (v.expect === 'malformed') {
      // BOTH entry points must refuse the broken rule.
      let validateThrew = false
      try {
        validate(v.rule)
      } catch (e) {
        validateThrew = e instanceof DcqlMalformedError
      }
      let evaluateThrew = false
      try {
        evaluateIdentityScoped(v.rule, views(v), v.identity)
      } catch (e) {
        evaluateThrew = e instanceof DcqlMalformedError
      }
      if (validateThrew && evaluateThrew) passed++
      else
        failures.push(
          `ident/${v.name}: expected malformed ` +
            `(validate threw=${validateThrew}, evaluateIdentityScoped threw=${evaluateThrew})`,
        )
    } else {
      const actual = evaluateIdentityScoped(v.rule, views(v), v.identity) ? 'grant' : 'deny'
      if (actual === v.expect) passed++
      else failures.push(`ident/${v.name}: expected ${v.expect}, got ${actual}`)
    }
  } catch (e) {
    failures.push(
      `ident/${v.name}: unexpected error ${e instanceof Error ? e.message : String(e)}`,
    )
  }
}

// ─── commitment vectors (cross-language known-answer) ────────────────────────

for (const v of corpus.commitment) {
  try {
    const canon = canonicalize(v.rule)
    if (canon !== v.canonical) {
      failures.push(
        `commit/${v.name}: canonical form differs\n    expected ${v.canonical}\n    got      ${canon}`,
      )
      continue
    }
    // The shipped function must reach the reference answer BY ITSELF — including
    // its own grammar dispatch. Passing the pre-canonicalised form would test
    // canonicalize() twice and the dispatch not at all.
    const got = ruleCommitment(v.salt, v.rule)
    if (got !== v.commitment) {
      failures.push(
        `commit/${v.name}: ruleCommitment differs\n    expected ${v.commitment}\n    got      ${got}`,
      )
      continue
    }
    passed++
  } catch (e) {
    failures.push(
      `commit/${v.name}: unexpected error ${e instanceof Error ? e.message : String(e)}`,
    )
  }
}

// ─── properties the JSON cannot express ──────────────────────────────────────

// The cap is in BYTES, not UTF-16 code units. A rule of 3000 multi-byte characters is
// under the JS `.length` limit and over the real one — if this file measured
// `.length`, it would accept a rule the reference implementation refuses.
{
  const wide = `{"credentials":[{"id":"${'é'.repeat(3000)}","format":"jwt_vc_json"}]}`
  if (wide.length < 4096 && new TextEncoder().encode(wide).length > 4096) {
    let threw = false
    try {
      validate(wide)
    } catch (e) {
      threw = e instanceof DcqlMalformedError && /bytes \(max 4096\)/.test(e.message)
    }
    if (threw) passed++
    else failures.push('oversized rule measured in BYTES: expected malformed with a byte count')
  } else {
    failures.push('oversized-rule probe is not exercising the byte-vs-length distinction')
  }
}

// A present-but-null claim is PRESENT. Collapsing absent and null into `undefined` is
// the obvious TS shortcut and would deny where the reference implementation grants.
// (The ["iss"] entry is the mandatory constraint, in its open form.)
{
  const rule =
    '{"credentials":[{"id":"a","format":"jwt_vc_json","claims":[{"path":["iss"]},{"path":["x"]}]}]}'
  const cred = jsonCredential({
    format: 'jwt_vc_json',
    types: [],
    body: {iss: 'did:web:hr.acme.example', x: null},
  })
  if (evaluate(rule, [cred])) passed++
  else failures.push('present-but-null claim: expected grant (null is a PRESENT claim)')
}

// A legacy kk-DCQL rule must NOT parse as OID4VP — this is what makes the commitment
// dispatch safe. If it did, every existing slot's hash would silently change.
{
  let threw = false
  try {
    validate('{"required_scope":"EmployeeOf:dept=Engineering"}')
  } catch (e) {
    threw = e instanceof DcqlMalformedError
  }
  if (threw) passed++
  else failures.push('a legacy kk-DCQL rule parsed as OID4VP — the grammar dispatch is unsafe')
}

// ─── report ──────────────────────────────────────────────────────────────────

const total =
  corpus.evaluation.length +
  corpus.scope_matcher.length +
  corpus.identity_scoped.length +
  corpus.commitment.length +
  3
if (failures.length > 0) {
  console.error(`OID4VP-DCQL conformance: ${failures.length} FAILED of ${total}`)
  for (const f of failures) console.error(`  ✗ ${f}`)
  process.exit(1)
}
console.log(
  `OID4VP-DCQL conformance: ${passed}/${total} passed ` +
    `(${corpus.evaluation.length} evaluation, ${corpus.scope_matcher.length} scope-matcher, ` +
    `${corpus.identity_scoped.length} identity-scoped, ${corpus.commitment.length} commitment, ` +
    `3 properties)`,
)
