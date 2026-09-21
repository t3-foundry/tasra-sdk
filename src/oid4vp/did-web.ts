// `did:web` resolution for the Verifier Agent's identity: `did:web:<host>` → `https://<host>/.well-known/did.json`
// (path form → `https://<host>/<path>/did.json`), and the verification key a JAR's `kid` names.
// The verifier-agent serves the set document itself, derived from the on-chain verifier set, so every wallet
// sees identical bytes. Since gap-closure P5.3 (2026-09-10) a verification method is named by its
// KEY — `did:web:<host>#z6Mk…`, the key's did:key id — so a join/leave of the verifier set never
// changes what a fragment means; a cached document or an in-flight JAR still resolves its signer.
// (`#verifier-N`, the address-sorted position, is the legacy encoding a deployment may still pin.)
// The lookup here is by id, whatever the encoding.

import {b64url, type Jwk} from './jose.js'
import {base58Decode} from './jose.js'

export interface DidDocument {
  id: string
  verificationMethod?: Array<{id: string; type?: string; controller?: string; publicKeyJwk?: Jwk; publicKeyMultibase?: string}>
  authentication?: Array<string | {id: string}>
  assertionMethod?: Array<string | {id: string}>
}

/** The HTTPS URL a `did:web` resolves from (W3C did:web method §3.2). */
export function didWebUrl(did: string): string {
  const m = /^did:web:(.+)$/.exec(did.split('#')[0]!)
  if (!m) throw new Error(`not a did:web: ${did}`)
  const segments = m[1]!.split(':').map(s => decodeURIComponent(s))
  const host = segments[0]!
  const path = segments.slice(1)
  return path.length === 0 ? `https://${host}/.well-known/did.json` : `https://${host}/${path.join('/')}/did.json`
}

export interface ResolveOpts {
  fetchImpl?: typeof fetch
  /** Allow `http://` for a loopback host (tests, local fleets); never for a public host. */
  allowInsecureLoopback?: boolean
}

/** Fetch and minimally validate a `did:web` document. */
export async function resolveDidWeb(did: string, opts: ResolveOpts = {}): Promise<DidDocument> {
  let url = didWebUrl(did)
  if (opts.allowInsecureLoopback && /^https:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url)) url = url.replace(/^https:/, 'http:')
  const f = opts.fetchImpl ?? fetch
  const res = await f(url, {headers: {Accept: 'application/json'}})
  if (!res.ok) throw new Error(`did:web resolution ${url} → HTTP ${res.status}`)
  const doc = (await res.json()) as DidDocument
  if (doc.id !== did.split('#')[0]) throw new Error(`did:web document id ${doc.id} != ${did}`)
  return doc
}

/** The JWK behind `kid` (a full DID URL or a `#fragment`) in `doc`. */
export function verificationKey(doc: DidDocument, kid: string): Jwk {
  const frag = kid.includes('#') ? kid.slice(kid.indexOf('#')) : kid
  const vm = (doc.verificationMethod ?? []).find(v => v.id === kid || v.id === frag || v.id.endsWith(frag))
  if (!vm) throw new Error(`did document ${doc.id} has no verification method ${kid}`)
  if (vm.publicKeyJwk) return vm.publicKeyJwk
  if (vm.publicKeyMultibase) {
    const raw = base58Decode(vm.publicKeyMultibase.replace(/^z/, ''))
    if (raw[0] === 0xed && raw[1] === 0x01) return {kty: 'OKP', crv: 'Ed25519', x: b64url(raw.slice(2))}
    throw new Error('unsupported publicKeyMultibase codec')
  }
  throw new Error(`verification method ${vm.id} carries no key material`)
}
