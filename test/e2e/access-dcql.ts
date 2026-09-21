// E2E: DCQL access control at the verifier.
//
//   - A presentation that SATISFIES the slot rule yields a JWT whose scope
//     carries the required claim.
//   - A presentation that FAILS the rule must NEVER yield a usable token
//     silently. The honest outcome is a 4xx denial; the demo's byzantine
//     verifier instead returns a token PLUS a self-incriminating
//     `fault_statement` (the input to the slashing path). Both are
//     acceptable; a clean token with no fault_statement is the violation.
//
// Run: tsx test/e2e/access-dcql.ts

import {Suite} from '../fleet/_assert.ts'
import {ENGINEERING_RULE, engineeringPresentation, gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {decodeJwtClaims} from '../../src/auth/verifier.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: DCQL access control')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

async function verify(url: string, presentation: unknown) {
  const res = await fetch(`${url}/v1/verify`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({dcql_rule: ENGINEERING_RULE, presentation}),
    signal: AbortSignal.timeout(6000),
  })
  let body: Record<string, unknown> = {}
  try {
    body = (await res.json()) as Record<string, unknown>
  } catch {
    /* non-JSON body */
  }
  return {status: res.status, body}
}

// ── happy path: an Engineering employee gets a scoped token ───────────────────
{
  const verifier = cfg.verifierUrls[0]!
  const {status, body} = await verify(verifier, engineeringPresentation('did:demo:alice'))
  const token = (body.token ?? body.jwt) as string | undefined
  s.ok('passing VP is accepted (2xx)', status >= 200 && status < 300, `HTTP ${status}`)
  s.ok('passing VP returns a token', !!token)
  if (token) {
    const claims = decodeJwtClaims(token)
    const scope = Array.isArray(claims?.scope) ? claims!.scope.join(' ') : String(claims?.scope ?? '')
    s.ok('token scope carries the required claim', scope.includes('EmployeeOf:dept=Engineering'), scope)
    s.eq('token subject is the holder', String(claims?.sub ?? ''), 'did:demo:alice')
  }
}

// ── denial invariant: a failing VP never yields a silent usable token ─────────
const failingVp = {
  holder: 'did:demo:mallory',
  credentials: [
    {issuer: 'did:web:hr.acmecorp.example', credential_type: 'EmployeeOf', claims: {dept: 'Sales'}},
  ],
}
for (const verifier of cfg.verifierUrls) {
  const short = verifier.replace(/^https?:\/\//, '')
  const {status, body} = await verify(verifier, failingVp)
  const token = (body.token ?? body.jwt) as string | undefined
  const fault = body.fault_statement
  if (status >= 400 || !token) {
    s.ok(`verifier ${short}: failing VP denied (HTTP ${status})`, true)
  } else if (fault) {
    // Mis-issued, but emitted the fault_statement that lets a challenger slash
    // it. Acceptable  — surfaced, not silent.
    s.ok(`verifier ${short}: mis-issued but emitted a fault_statement (byzantine, slashable)`, true)
    s.info(`fault verifier=${(fault as {verifier?: string}).verifier ?? '?'}`)
  } else {
    s.ok(`verifier ${short}: failing VP must not yield a silent token`, false, 'got a token with no fault_statement')
  }
}

s.done()
