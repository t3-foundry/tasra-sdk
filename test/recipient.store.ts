// Recipient-side DCQL access gate — unit tests.
//
// Proves the platform-blind recipient path using OID4VP-DCQL rules and the
// structured CredentialView interface. Pure/local — no network.
//
// Run:  tsx test/recipient.store.ts   — exits non-zero on any failure.

import {RecipientStore, canAccess, validateRule, type HeldCredential} from '../src/recipient/store.ts'
import {DcqlMalformedError, select, jsonCredential} from '../src/auth/oid4vp.ts'

let passed = 0
const failures: string[] = []
function check(name: string, cond: boolean): void {
  if (cond) passed++
  else failures.push(name)
}
function throws(name: string, fn: () => void, is: (e: unknown) => boolean): void {
  try {
    fn()
    failures.push(`${name}: expected throw, none`)
  } catch (e) {
    check(name, is(e))
  }
}

// Helper: build an OID4VP-DCQL rule requiring a credential with given issuer and optional type
function rule(opts: {issuer: string; type?: string; claimPath?: string; claimValues?: unknown[]}): string {
  const claims: Array<{path: string[]; values?: unknown[]}> = [
    {path: ['iss'], values: [opts.issuer]},
  ]
  if (opts.claimPath) {
    const entry: {path: string[]; values?: unknown[]} = {path: [opts.claimPath]}
    if (opts.claimValues) entry.values = opts.claimValues
    claims.push(entry)
  }
  const cred: Record<string, unknown> = {
    id: 'c1',
    format: 'jwt_vc_json',
    claims,
  }
  if (opts.type) {
    cred.meta = {type_values: [[opts.type]]}
  }
  return JSON.stringify({credentials: [cred]})
}

const eng: HeldCredential = {
  format: 'jwt_vc_json',
  types: ['EmployeeCredential'],
  body: {
    iss: 'did:web:hr.acmecorp',
    dept: 'Engineering',
    role: 'engineer',
  },
}
const proj: HeldCredential = {
  format: 'jwt_vc_json',
  types: ['MembershipCredential'],
  body: {
    iss: 'did:web:project-phoenix',
    project: 'phoenix',
    role: 'member',
  },
}

// Single credential: matching issuer grants, non-matching denies.
{
  const s = new RecipientStore([eng])
  check('issuer match grants', s.satisfies(rule({issuer: 'did:web:hr.acmecorp'})))
  check('issuer miss denies', !s.satisfies(rule({issuer: 'did:web:other'})))
}

// Type matching.
{
  const s = new RecipientStore([eng])
  check('type match grants', s.satisfies(rule({issuer: 'did:web:hr.acmecorp', type: 'EmployeeCredential'})))
  check('type miss denies', !s.satisfies(rule({issuer: 'did:web:hr.acmecorp', type: 'MembershipCredential'})))
}

// Claim path matching.
{
  const s = new RecipientStore([eng])
  check('claim presence match', s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'dept'})))
  check('claim value match', s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'dept', claimValues: ['Engineering']})))
  check('claim value miss', !s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'dept', claimValues: ['Sales']})))
  check('claim absent denies', !s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'nonexistent'})))
}

// Multi-credential: each credential is evaluated independently.
{
  const s = new RecipientStore([eng, proj])
  check('issuer from 1st cred', s.satisfies(rule({issuer: 'did:web:hr.acmecorp'})))
  check('issuer from 2nd cred', s.satisfies(rule({issuer: 'did:web:project-phoenix'})))
  check('unheld issuer denies', !s.satisfies(rule({issuer: 'did:web:rogue'})))
}

// credential_sets: alternatives.
{
  const twoCredRule = JSON.stringify({
    credentials: [
      {id: 'emp', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.acmecorp']}]},
      {id: 'mem', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:project-phoenix']}]},
    ],
    credential_sets: [
      {options: [['emp'], ['mem']]},
    ],
  })
  const s1 = new RecipientStore([eng])
  check('credential_sets: first alternative satisfies', s1.satisfies(twoCredRule))
  const s2 = new RecipientStore([proj])
  check('credential_sets: second alternative satisfies', s2.satisfies(twoCredRule))
}

// Empty store: only denies (no credentials to match any query).
{
  const empty = new RecipientStore([])
  check('empty store: any rule denies', !empty.satisfies(rule({issuer: 'did:web:any'})))
}

// canAccess: fail-closed on malformed (returns false, does not throw).
{
  check('canAccess grants on match', canAccess(rule({issuer: 'did:web:project-phoenix'}), [proj]))
  check('canAccess denies on miss', !canAccess(rule({issuer: 'did:web:nope'}), [proj]))
  check('canAccess fail-closed on malformed rule', !canAccess('not valid json {{{', [eng]))
  check('canAccess accepts a RecipientStore too', canAccess(rule({issuer: 'did:web:hr.acmecorp'}), new RecipientStore([eng])))
}

// satisfies() throws on a malformed rule (distinguishes deny from broken-rule).
throws(
  'satisfies throws DcqlMalformedError on bad rule',
  () => new RecipientStore([eng]).satisfies('not valid json {{{'),
  e => e instanceof DcqlMalformedError,
)

// fromJwtBodies: builds credentials from parsed JWT bodies.
{
  const s = RecipientStore.fromJwtBodies([
    {type: ['EmployeeCredential'], iss: 'did:web:hr.acmecorp', dept: 'Engineering'},
  ])
  check('fromJwtBodies: issuer match', s.satisfies(rule({issuer: 'did:web:hr.acmecorp'})))
  check('fromJwtBodies: claim match', s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'dept', claimValues: ['Engineering']})))
  check('fromJwtBodies: absent claim denies', !s.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'admin'})))
}

// add() chains.
{
  const s = new RecipientStore([]).add(eng).add(proj)
  check('add() chains', s.satisfies(rule({issuer: 'did:web:project-phoenix'})))
}

// views() returns the credential views.
{
  const s = new RecipientStore([eng, proj])
  check('views() returns correct count', s.views().length === 2)
}

// ─── select() ──────────────────────────────────────────────────────────────

// select: satisfied — single credential query.
{
  const creds = [eng, proj].map(h => jsonCredential(h))
  const r = rule({issuer: 'did:web:hr.acmecorp'})
  const s = select(r, creds)
  check('select: satisfied', s.satisfied)
  check('select: returns one credential', s.credentials.length === 1)
  check('select: no unsatisfied', s.unsatisfied.length === 0)
}

// select: unsatisfied — no credential matches.
{
  const creds = [eng].map(h => jsonCredential(h))
  const r = rule({issuer: 'did:web:rogue'})
  const s = select(r, creds)
  check('select: unsatisfied', !s.satisfied)
  check('select: empty credentials on miss', s.credentials.length === 0)
  check('select: reports unsatisfied query', s.unsatisfied.length === 1)
}

// select: credential_sets — picks cheapest option.
{
  const creds = [eng, proj].map(h => jsonCredential(h))
  const twoCredRule = JSON.stringify({
    credentials: [
      {id: 'emp', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.acmecorp']}]},
      {id: 'mem', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:project-phoenix']}]},
    ],
    credential_sets: [
      {options: [['emp', 'mem'], ['emp']]},
    ],
  })
  const s = select(twoCredRule, creds)
  check('select credential_sets: satisfied', s.satisfied)
  check('select credential_sets: picks cheapest option (1 cred)', s.credentials.length === 1)
}

// select: empty credentials — unsatisfied.
{
  const s = select(rule({issuer: 'did:web:any'}), [])
  check('select: empty credentials unsatisfied', !s.satisfied)
}

// validateRule: the explicit client-side rule check.
//
// This is what a slot author calls BEFORE creating a slot. A rule that only fails at
// provisioning time costs the slot, so the check has to be available on its own rather than
// only as a side effect of evaluating against credentials.
{
  let threw = false
  try {
    validateRule(rule({issuer: 'did:web:hr.acmecorp'}))
  } catch {
    threw = true
  }
  check('validateRule: a well-formed rule returns normally', !threw)
  // It must NOT need credentials — validity is a property of the rule alone.
  check('validateRule: returns undefined, not a verdict', validateRule(rule({issuer: 'did:web:x'})) === undefined)
  throws('validateRule: malformed JSON throws DcqlMalformedError', () => validateRule('{not json'), e => e instanceof DcqlMalformedError)
  throws('validateRule: a rule with no credentials array throws', () => validateRule('{}'), e => e instanceof DcqlMalformedError)
  throws(
    'validateRule: a credential query with no id throws',
    () => validateRule(JSON.stringify({credentials: [{format: 'jwt_vc_json', claims: []}]})),
    e => e instanceof DcqlMalformedError,
  )
  // ⚠ A bare kk-DCQL string is NOT an OID4VP-DCQL rule. It is refused here, which is what
  // stops a caller assuming the two grammars are interchangeable.
  throws('validateRule: a bare kk-DCQL string is refused', () => validateRule('verify:demo'), e => e instanceof DcqlMalformedError)
}

// canAccess: fail-closed applies to a MALFORMED RULE — and to nothing else.
{
  const store = new RecipientStore([eng])
  check('canAccess: a malformed rule denies rather than throwing', canAccess('{not json', store) === false)
  check('canAccess: accepts a bare credential list too', canAccess(rule({issuer: 'did:web:hr.acmecorp'}), [eng]) === true)
  check('canAccess: a bare list that does not satisfy denies', canAccess(rule({issuer: 'did:web:other'}), [eng]) === false)
  // The documented asymmetry: satisfies() THROWS on a malformed rule (a slot-author bug the
  // node reports as 400), canAccess() denies. Both behaviours are relied on.
  throws('satisfies: a malformed rule throws', () => new RecipientStore([eng]).satisfies('{not json'), e => e instanceof DcqlMalformedError)

  // ⚠ An UNEXPECTED error must propagate, not be swallowed as a deny. Fail-closed on a
  // malformed rule is a deliberate policy; fail-closed on a bug in the caller's credential
  // would silently turn a broken store into "access denied" — indistinguishable from a
  // correct refusal, and undebuggable.
  const exploding = {
    format: 'jwt_vc_json',
    types: ['VerifiableCredential'],
    claim(): never {
      throw new TypeError('credential store is corrupt')
    },
  }
  throws(
    'canAccess: a non-DCQL error propagates rather than becoming a deny',
    () => canAccess(rule({issuer: 'did:web:hr.acmecorp'}), new RecipientStore([exploding])),
    e => e instanceof TypeError,
  )
}

// The store's two accepted credential shapes, on both entry points.
{
  const view = jsonCredential(eng)
  // A CredentialView is taken as-is; a HeldCredential is converted. Confusing the two would
  // either double-wrap (breaking `claim`) or pass a raw object the evaluator cannot read.
  check('constructor: a CredentialView is kept as the same object', new RecipientStore([view]).views()[0] === view)
  check('constructor: a HeldCredential is converted to a view', typeof new RecipientStore([eng]).views()[0]?.claim === 'function')
  check('constructor: defaults to empty', new RecipientStore().views().length === 0)

  const s = new RecipientStore()
  check('add: returns this for chaining', s.add(eng).add(view) === s)
  check('add: both shapes land in the store', s.views().length === 2)
  check('add: the view was not re-wrapped', s.views()[1] === view)
  check('add: a credential added later is evaluated', s.satisfies(rule({issuer: 'did:web:hr.acmecorp'})))

  // fromJwtBodies is the convenience for a wallet holding parsed JWT payloads.
  const fromBodies = RecipientStore.fromJwtBodies([
    {type: ['VerifiableCredential', 'EmployeeCredential'], iss: 'did:web:hr.acmecorp', dept: 'Engineering'},
  ])
  check('fromJwtBodies: builds a satisfying store', fromBodies.satisfies(rule({issuer: 'did:web:hr.acmecorp'})))
  check('fromJwtBodies: the body becomes the claim source', fromBodies.satisfies(rule({issuer: 'did:web:hr.acmecorp', claimPath: 'dept', claimValues: ['Engineering']})))
  check('fromJwtBodies: types come from the type array', fromBodies.views()[0]?.types.includes('EmployeeCredential') === true)
  check('fromJwtBodies: an empty list is an empty store', RecipientStore.fromJwtBodies([]).views().length === 0)
}

const total = passed + failures.length
if (failures.length > 0) {
  console.error(`recipient-store: ${passed}/${total} passed\n`)
  for (const f of failures) console.error('  FAIL:', f)
  process.exit(1)
}
console.log(`recipient-store: ${passed}/${total} passed`)
