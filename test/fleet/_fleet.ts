// Fleet discovery + config for the live-fleet test suites.
//
// Config comes from the environment only. These suites run against any reachable
// deployment and deliberately know nothing about how it was brought up — no file
// is read from another repository and no external binary is invoked.
//
// Addresses are read straight out of the environment by addressBookFromEnv, so
// TASRA_KEY_REGISTRY, TASRA_SETTLEMENT and friends work the same way.

import {existsSync, readFileSync} from 'node:fs'
import {dirname, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {ed25519} from '@noble/curves/ed25519'
import {addressBookFromEnv, type AddressBook} from '../../src/chain/deployments.ts'
import {verifyPresentation, verifyVpJwt, type IssuedToken} from '../../src/auth/verifier.ts'
import {createHolderProof, ed25519DidKey, type HolderSigner} from '../../src/auth/holderProof.ts'
import {createTasraWriteClient} from '../../src/chain/write.ts'
import {b64urlDecode, signCompactJws} from '../../src/oid4vp/jose.ts'
import type {Suite} from './_assert.ts'

export interface FleetConfig {
  nodeUrls: string[]
  verifierUrls: string[]
  explorerApi: string
  rpcUrl: string
  chainId: number
  slotId: `0x${string}` // demo BLS slot, 0x-prefixed lowercase
  // BN254 GOVERNANCE slot (PlatformExecutor path). Empty when the fleet was brought up
  // without one. ⚠ Not a key slot: keepers never DKG it, so /v1/keys/<id>/public stays empty and
  // each node signs from the share it loaded off disk (api.governance_key_path).
  governanceSlotId: `0x${string}`
  /**
   * rule salt for the fleet's demo slot. Empty when the fleet predates the export — a
   * suite that needs to (re-)provision a fleet slot's rule cannot do so without it, because the
   * keeper recomputes `keccak256(DOMAIN ‖ salt ‖ rule)` and refuses the mismatch.
   */
  ruleSalt: string
  /**
   * The governance slot's OWN rule + salt (chain.env GOVERNANCE_DCQL_RULE / GOVERNANCE_RULE_SALT).
   * ⚠ It no longer shares the demo slot's commitment: the demo rule is an SD-JWT membership query
   * no bearer JWT satisfies, and governance partial-sign is JWT-authorized. Empty on older fleets.
   */
  governanceRule: string
  governanceRuleSalt: string
  adminSecret: string
  deployPk: string
  deployAddr: string
  /** Faucet service base URL (funds a sovereign client account: gas + TSRA). */
  faucetUrl: string
  /** Signed-VC issuer (prod path): the key the verifier's anchor trusts. */
  issuerKey: string
  issuerDid: string
  /**
   * The deployment's Ed25519 JWT issuer seed, and the `iss`/`aud` its keepers
   * verify against. No default: a wrong seed reads as an authorization bug.
   */
  jwtSigningKey: string
  jwtIss: string
  jwtAud: string
  book: AddressBook
  /** Every string-valued environment variable, for deployment-specific lookups. */
  raw: Record<string, string>
}

// Keeper CANDIDATES. How many of a deployment's keepers actually run is a
// bring-up choice, so gate() probes this list and trims it to the live ones:
// FROST paths size n = nodeUrls.length, and one dead entry breaks every DKG.
// Set TASRA_NODE_URLS to pin an exact list (no trimming).
const DEFAULT_NODES = [8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100].map(p => `http://localhost:${p}`)
const DEFAULT_VERIFIERS = [8181, 8182, 8183].map(p => `http://localhost:${p}`)

function splitUrls(v: string | undefined, fallback: string[]): string[] {
  if (!v) return fallback
  return v.split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean)
}

function hex0x(v: string | undefined): `0x${string}` {
  const s = (v ?? '').toLowerCase()
  return (s.startsWith('0x') ? s : s ? `0x${s}` : '') as `0x${string}`
}

/**
 * Every string-valued environment variable. Suites read deployment-specific
 * addresses off this (`cfg.raw.BONDING_CURVE`), so an unset one is `undefined`
 * and the suite's own precondition check names it.
 */
function environment(): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) if (typeof v === 'string') out[k] = v
  return out
}

/**
 * Read the deployment's coordinates from the environment.
 *
 * Endpoints default to a loopback deployment; everything identifying a specific
 * deployment (slot ids, salts, keys, addresses) has NO default, because a wrong
 * default here surfaces much later as an unrelated-looking authorization failure.
 * Suites assert the preconditions they need and name the variable that is missing.
 */
/** Keys the CALLER set, captured at import — these always win over the file. */
const CALLER_ENV = new Set(Object.keys(process.env))

/**
 * The fleet's `chain.env`, when there is one. Only a LOCAL fleet has this file; a third party
 * pointing the SDK at a real deployment has no such thing, which is why the config below reads
 * environment variables and this is a bridge rather than the primary source.
 */
export const chainEnvPath =
  process.env.KK_CHAIN_ENV ??
  resolve(
    dirname(fileURLToPath(import.meta.url)),
    '..', '..', '..', '..', 'managination', 'keykeeper-network',
    'lab', 'fleet', 'credentials', 'chain.env',
  )

/**
 * Publish `chain.env` into `process.env` so this config can see a local fleet.
 *
 * ⚠⚠ WITHOUT THIS, EVERY FLEET-DERIVED VALUE IS SILENTLY EMPTY and the failure lands somewhere
 * else entirely. A cert run showed it twice over: the verify harness reported
 * `slotKeyAnchored=false` against a fleet whose slot WAS anchored (empty `slotId`), and six
 * scenarios died in `createWalletSlot` with "pass either privateKey or wallet" (empty
 * `deployPk`). The endpoints meanwhile answered 200 on their localhost DEFAULTS, so a config
 * that was never populated reads as a broken fleet.
 *
 * Re-runs on every call because the file is written DURING fleet provisioning: a value absent
 * on one read is present on the next. A key the caller set is never overwritten, so certify's
 * explicit environment still wins.
 */
export function hydrateFleetEnv(): void {
  if (!existsSync(chainEnvPath)) return
  // chain.env's own names feed `addressBookFromEnv` directly. For the config's TASRA_* reads the
  // rule is a PREFIX -- `JWT_SIGNING_KEY` is `TASRA_JWT_SIGNING_KEY`, and so on -- with only
  // these four genuine renames.
  //
  // ⚠⚠ A HAND-LISTED MAP WAS TRIED FIRST AND WAS INCOMPLETE TWICE. It shipped without
  // JWT_SIGNING_KEY, and three checks then failed on "no JWT issuer seed" -- a key nobody
  // noticed missing until the code that needed it ran. Enumerating the keys that happen to be
  // used today cannot cover the one added tomorrow; deriving the name does.
  const RENAMED: Record<string, string> = {
    DEMO_SLOT_ID: 'TASRA_SLOT_ID',
    DEMO_RULE_SALT: 'TASRA_RULE_SALT',
    CHAIN_RPC: 'TASRA_RPC_URL',
    GOVERNANCE_DCQL_RULE: 'TASRA_GOVERNANCE_RULE',
  }
  for (const line of readFileSync(chainEnvPath, 'utf8').split(/\r?\n/)) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    const eq = t.indexOf('=')
    if (eq < 0) continue
    const k = t.slice(0, eq).replace(/^export\s+/, '').trim()
    let v = t.slice(eq + 1).trim()
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1)
    if (!CALLER_ENV.has(k)) process.env[k] = v
    // Already TASRA_-prefixed keys (TASRA_VAULT_*) must not become TASRA_TASRA_*.
    const aliased = RENAMED[k] ?? (k.startsWith('TASRA_') ? k : `TASRA_${k}`)
    if (aliased !== k && !CALLER_ENV.has(aliased)) process.env[aliased] = v
  }

  // Identities the LOCAL FLEET fixes but never writes to chain.env.
  //
  // The demo issuer is a fixed keypair whose public half is baked into the fleet's verifier as a
  // `[[vc_trust_anchors]]` entry (AIct1Lf9…). It is a FIXTURE, not a secret: a wallet credential
  // signed with any other key is refused by that anchor, so there is nothing to protect and
  // nothing else that would work.
  //
  // ⚠ THIS BELONGS HERE, NOT IN THE CONFIG'S DEFAULTS. The config deliberately defaults
  // deployment-identifying values to empty, because a wrong default surfaces much later as an
  // unrelated-looking authorization failure. That rule is right and stays: these are applied
  // ONLY when a local fleet's chain.env exists, so a caller pointing the SDK at a real
  // deployment still gets nothing invented for it.
  const fleetFixture: Record<string, string> = {
    TASRA_ISSUER_KEY: 'UoHyiECxzBuy0vgXeAHcmqYqLUrnqS2-uzsxuPm9nFc',
    TASRA_ISSUER_DID: 'did:web:hr.acmecorp.example',
    TASRA_ADMIN_SECRET: 'demo-admin-secret-change-me',
  }
  for (const [k, v] of Object.entries(fleetFixture)) {
    if (!CALLER_ENV.has(k) && !process.env[k]) process.env[k] = v
  }
}

export function loadFleetConfig(): FleetConfig {
  hydrateFleetEnv()
  const raw = environment()
  return {
    nodeUrls: splitUrls(process.env.TASRA_NODE_URLS, DEFAULT_NODES),
    verifierUrls: splitUrls(process.env.TASRA_VERIFIER_URLS, DEFAULT_VERIFIERS),
    explorerApi: (process.env.TASRA_EXPLORER_API ?? 'http://localhost:8090/api').replace(/\/$/, ''),
    rpcUrl: process.env.TASRA_RPC_URL ?? 'http://localhost:8545',
    chainId: Number(process.env.TASRA_CHAIN_ID ?? 1337),
    slotId: hex0x(process.env.TASRA_SLOT_ID),
    governanceSlotId: hex0x(process.env.TASRA_GOVERNANCE_SLOT_ID),
    ruleSalt: (process.env.TASRA_RULE_SALT ?? '').toLowerCase(),
    governanceRule: process.env.TASRA_GOVERNANCE_RULE ?? '',
    governanceRuleSalt: (process.env.TASRA_GOVERNANCE_RULE_SALT ?? '').toLowerCase(),
    adminSecret: process.env.TASRA_ADMIN_SECRET ?? '',
    deployPk: process.env.TASRA_DEPLOY_PK ?? '',
    deployAddr: (process.env.TASRA_DEPLOY_ADDR ?? '').toLowerCase(),
    faucetUrl: (process.env.TASRA_FAUCET ?? 'http://localhost:8552').replace(/\/$/, ''),
    // Must be the key the target verifier's issuer anchor trusts, or every
    // presentation is refused as an unknown issuer.
    issuerKey: process.env.TASRA_ISSUER_KEY ?? '',
    issuerDid: process.env.TASRA_ISSUER_DID ?? '',
    jwtSigningKey: process.env.TASRA_JWT_SIGNING_KEY ?? '',
    jwtIss: process.env.TASRA_JWT_ISS ?? '',
    jwtAud: process.env.TASRA_JWT_AUD ?? '',
    book: addressBookFromEnv(raw),
    raw,
  }
}

async function probe(url: string, ms = 3000): Promise<number | null> {
  try {
    const res = await fetch(url, {signal: AbortSignal.timeout(ms)})
    return res.status
  } catch {
    return null
  }
}

/**
 * Reachability gate. Returns true when the fleet answers. When it's down the
 * suite SKIPs (and the caller should exit 0) — unless TASRA_FLEET_REQUIRED=1, in
 * which case it records a failure so CI goes red.
 *
 * Without a TASRA_NODE_URLS override, cfg.nodeUrls is a candidate set, so this
 * also trims it IN PLACE to the keepers answering /readyz — downstream FROST DKG
 * sizes n from this list.
 */
export async function gate(suite: Suite, cfg: FleetConfig): Promise<boolean> {
  await trimToLiveKeepers(cfg)
  const node = cfg.nodeUrls[0]
  const verifier = cfg.verifierUrls[0]
  const nodeStatus = node ? await probe(`${node}/readyz`) : null
  const verStatus = verifier ? await probe(`${verifier}/health`) : null
  const up = nodeStatus === 200 && verStatus === 200
  if (up) return true
  const detail = `node ${node}/readyz=${nodeStatus ?? 'DOWN'}, verifier ${verifier}/health=${verStatus ?? 'DOWN'}`
  if (process.env.TASRA_FLEET_REQUIRED) {
    suite.ok(`fleet reachable (${detail})`, false)
    return false
  }
  suite.skip('suite', `fleet not reachable — ${detail}. Point TASRA_NODE_URLS/TASRA_VERIFIER_URLS at a running deployment`)
  return false
}

/**
 * Trim `cfg.nodeUrls` IN PLACE to the keepers answering /readyz.
 *
 * Without a TASRA_NODE_URLS override, cfg.nodeUrls is a CANDIDATE set, so anything
 * that sizes a threshold from it MUST trim first — an on-chain FROST slot created
 * with n = 10 against a 5-keeper fleet reverts on the draw, and one that does get
 * created never DKGs ("participants (5) != threshold.n").
 *
 * `gate()` calls this, so suites get it for free; a script that skips the gate
 * has to call it itself.
 */
export async function trimToLiveKeepers(cfg: FleetConfig): Promise<void> {
  if (process.env.TASRA_NODE_URLS) return // explicit list: honour it verbatim
  const live = (
    await Promise.all(cfg.nodeUrls.map(async u => ((await probe(`${u}/readyz`)) === 200 ? u : null)))
  ).filter((u): u is string => u !== null)
  // none live → keep the candidates so the caller's "DOWN" detail names a URL
  if (live.length) cfg.nodeUrls = live
}

/** The demo slot's DCQL rule for verifier evaluation paths (/v1/verify, /v1/verify-vp-jwt). */
export const ENGINEERING_RULE = '{"credentials":[{"id":"demo","format":"jwt_vc_json","claims":[]}],"_kk_legacy":true}'

/** Build an Engineering employee presentation that satisfies the demo slot. */
export function engineeringPresentation(holder = 'did:demo:alice') {
  return {
    holder,
    credentials: [
      {
        issuer: 'did:web:hr.acmecorp.example',
        credential_type: 'EmployeeOf',
        claims: {dept: 'Engineering', employer: 'AcmeCorp'},
      },
    ],
  }
}

/**
 * Mint a real, node-acceptable JWT by presenting an Engineering VP to a
 * verifier. A passing VP is issued correctly by every verifier (the demo's
 * byzantine verifier only mis-issues for FAILING VPs), so verifierUrls[0] is
 * fine. The returned token's scope satisfies the demo slot's rule, so nodes
 * accept it for shard fetch / metering.
 */
export async function mintEngineeringJwt(
  cfg: FleetConfig,
  holder = 'did:demo:alice',
): Promise<IssuedToken> {
  const verifier = cfg.verifierUrls[0]
  if (!verifier) throw new Error('no verifier configured')
  return verifyPresentation(verifier, {
    dcql_rule: ENGINEERING_RULE,
    presentation: engineeringPresentation(holder),
  })
}

/**
 * Issue a signed JWT-VC, in the flat body shape the verifier expects:
 * `{iss, sub, iat, exp, credential_type, claims}` signed EdDSA by the issuer seed.
 *
 * Claim keys are sorted because the verifier reads them from a sorted map; keeping
 * the order stable here means a payload is reproducible across runs.
 */
export function issueVc(
  cfg: FleetConfig,
  opts: {holder: string; credentialType?: string; claims?: Record<string, string>; ttlSecs?: number},
): string {
  if (!cfg.issuerKey) {
    throw new Error('no issuer key: set TASRA_ISSUER_KEY to the base64url Ed25519 seed the verifier anchor trusts')
  }
  if (!cfg.issuerDid) throw new Error('no issuer DID: set TASRA_ISSUER_DID')
  const seed = b64urlDecode(cfg.issuerKey)
  if (seed.length !== 32) {
    throw new Error(`TASRA_ISSUER_KEY must decode to a 32-byte Ed25519 seed, got ${seed.length} bytes`)
  }
  const claims = opts.claims ?? {dept: 'Engineering', employer: 'AcmeCorp'}
  const sorted: Record<string, string> = {}
  for (const k of Object.keys(claims).sort()) sorted[k] = claims[k] as string
  const now = Math.floor(Date.now() / 1000)
  return signCompactJws(
    {typ: 'JWT'},
    {
      iss: cfg.issuerDid,
      sub: opts.holder,
      iat: now,
      exp: now + (opts.ttlSecs ?? 86400),
      credential_type: opts.credentialType ?? 'EmployeeOf',
      claims: sorted,
    },
    {alg: 'EdDSA', privateKey: seed},
  )
}

export function randomDidKeyHolder(): {holder: string; signer: HolderSigner} {
  const secretKey = ed25519.utils.randomPrivateKey()
  const holder = ed25519DidKey(ed25519.getPublicKey(secretKey))
  return {holder, signer: {alg: 'EdDSA', did: holder, secretKey}}
}

/**
 * PRODUCTION credential path: issue a signed Engineering VC to a holder DID,
 * prove live control of that DID's authentication key, and present both to
 * `/v1/verify-vp-jwt` for a node-acceptable JWT. Replaces mintEngineeringJwt on
 * a prod-profile fleet (unsigned `/v1/verify` is off).
 */
export async function mintSignedEngineeringJwt(
  cfg: FleetConfig,
  opts: {holder: string; signer: HolderSigner; rule?: string},
): Promise<IssuedToken> {
  const verifier = cfg.verifierUrls[0]
  if (!verifier) throw new Error('no verifier configured')
  const rule = opts.rule ?? ENGINEERING_RULE
  if (!cfg.jwtIss) throw new Error('no holder-proof audience: set TASRA_JWT_ISS to the verifier the deployment issues under')
  const audience = cfg.jwtIss
  const vc = issueVc(cfg, {holder: opts.holder, credentialType: 'EmployeeOf', claims: {dept: 'Engineering', employer: 'AcmeCorp'}})
  const holderProof = await createHolderProof(verifier, {signer: opts.signer, audience, credentials: [vc]})
  return verifyVpJwt(verifier, {dcql_rule: rule, holder: opts.holder, credentials: [vc], holder_proof: holderProof})
}

/**
 * Mint an EdDSA JWT locally from the deployment's issuer seed. Needed for the
 * operations the verifier does not gate: slot creation and slot-scoped
 * sign/decrypt during load tests.
 *
 * The keepers verify against the public half of this seed, so there is no shared
 * minting secret. Scope may be a string or an array; nodes accept both.
 */
export function mintLocalJwt(
  cfg: FleetConfig,
  opts: {sub?: string; scope?: string | string[]; ttlSecs?: number; signingKey?: string; iss?: string; aud?: string} = {},
): string {
  // No default seed, deliberately: a built-in constant would let anyone holding
  // this package mint an admin token against a real deployment.
  const seedSource = opts.signingKey ?? cfg.jwtSigningKey
  if (!seedSource) throw new Error('no JWT issuer seed: set TASRA_JWT_SIGNING_KEY to the deployment 32-byte Ed25519 seed')
  const seedHex = seedSource.replace(/^0x/, '')
  const seed = Buffer.from(seedHex, 'hex')
  if (seed.length !== 32) throw new Error(`TASRA_JWT_SIGNING_KEY must be a 32-byte hex seed, got ${seed.length} bytes`)
  const iss = opts.iss ?? cfg.jwtIss
  const aud = opts.aud ?? cfg.jwtAud
  if (!iss || !aud) throw new Error('no JWT iss/aud: set TASRA_JWT_ISS and TASRA_JWT_AUD')
  const now = Math.floor(Date.now() / 1000)
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const head = b64({typ: 'JWT', alg: 'EdDSA'})
  const body = b64({
    sub: opts.sub ?? 'did:demo:loadtest',
    iss,
    aud,
    iat: now,
    exp: now + (opts.ttlSecs ?? 3600),
    scope: opts.scope ?? ['admin', 'EmployeeOf', 'EmployeeOf:dept=Engineering'],
  })
  const sig = Buffer.from(ed25519.sign(new TextEncoder().encode(`${head}.${body}`), seed)).toString('base64url')
  return `${head}.${body}.${sig}`
}

/**
 * The DCQL rule the demo provisions on the nodes. Uses a `DcqlQuery` JSON shape
 * that passes the reference validator but NOT `oid4vp::validate` (the extra
 * `_kk_legacy` field trips the OID4VP `deny_unknown_fields`), so slots created with
 * this rule remain JWT-auth compatible (not committee-only). The credential query
 * with empty claims acts as a universal grant — any JWT scope satisfies it.
 */
export const SLOT_DCQL_RULE = '{"credentials":[{"id":"demo","format":"jwt_vc_json","claims":[]}],"_kk_legacy":true}'

export interface ProvisionResult {
  /** True when every node either filled the rule in or already carried it. */
  ok: boolean
  /** Nodes that answered 200 (`provisioned` or the idempotent no-op). */
  accepted: number
  /** `url → HTTP nnn: body` for each node that refused, verbatim. */
  errors: string[]
}

/**
 * Provision a slot's clear DCQL rule — and its rule salt — on `urls`.
 *
 * ⚠ `ruleSalt` is NOT optional for a slot created ON-CHAIN. The chain carries
 * `keccak256(DOMAIN ‖ salt ‖ rule)`, so a keeper recomputes that commitment and
 * REFUSES a rule whose salt does not reproduce it. Pass the salt the creator
 * minted (`createSlot`/`createSlotCommitReveal` return it; `tasra-cli slot
 * create` prints `rule_salt`; the demo fleet exports `DEMO_RULE_SALT` into
 * chain.env). It is no longer optional in any case: the local-slot path that
 * had no on-chain commitment (`POST /v1/dkg/trigger`, which committed under the
 * all-zero salt) was REMOVED, so every slot now carries a real commitment.
 *
 * ⚠ The outcome is RETURNED rather than swallowed on purpose. Provisioning is
 * setup, so every call site used to fire-and-forget it — and a refusal then
 * surfaced steps later as an opaque 403 ("rule not provisioned") from the
 * operation under test, which reads as a broken node instead of a broken setup.
 * Callers should assert `ok` and print `errors`.
 */
export async function provisionRule(
  urls: string[],
  slotId: string,
  rule: string,
  ruleSalt: string | undefined,
  jwt: string,
): Promise<ProvisionResult> {
  const body = JSON.stringify(ruleSalt ? {dcql_rule: rule, dcql_salt: ruleSalt} : {dcql_rule: rule})
  const results = await Promise.all(
    urls.map(async url => {
      try {
        const res = await fetch(`${url}/v1/keys/${slotId}/rule`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json', Authorization: `Bearer ${jwt}`},
          body,
          signal: AbortSignal.timeout(15000),
        })
        if (res.ok) return null
        return `${url} → HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`
      } catch (e) {
        return `${url} → ${(e as Error).message}`
      }
    }),
  )
  const errors = results.filter((r): r is string => r !== null)
  return {ok: errors.length === 0, accepted: urls.length - errors.length, errors}
}

/**
 * Discover which nodes currently hold this slot's shards. A committee node
 * answers 200 on /v1/keys/:id/public; a non-committee node 404s. The demo's
 * beacon-entropy can move the committee off nodes 1-3, so we never assume it.
 */
export async function discoverCommittee(
  cfg: FleetConfig,
  slot: string,
): Promise<string[]> {
  const clean = slot.startsWith('0x') ? slot : `0x${slot}`
  const checks = await Promise.all(
    cfg.nodeUrls.map(async url => ({
      url,
      status: await probe(`${url}/v1/keys/${clean}/public`),
    })),
  )
  return checks.filter(c => c.status === 200).map(c => c.url)
}

/**
 * Create an EXPORTABLE BLS slot under {@link SLOT_DCQL_RULE}, wait for its key, and provision the
 * rule + salt on the committee — for suites that exercise RAW shard export (`/v1/shards/key`)
 * with a bearer JWT.
 *
 * ⚠ Not the demo slot. The demo slot is exportable, but its rule is an SD-JWT membership query
 * that no JWT claim set satisfies, so every bearer shard fetch against it answers 403
 * "dcql_rule rejected caller". Exportability is fixed at birth and only the one-shot create sets it.
 */
export async function createExportableShardSlot(
  cfg: FleetConfig,
  provisionJwt: string,
  opts: {k?: number; n?: number; timeoutMs?: number} = {},
): Promise<{slotId: `0x${string}`; committee: string[]; mpkHex: string}> {
  if (!cfg.book.KeyRegistry || !cfg.deployPk) {
    throw new Error('need KEY_REGISTRY + DEPLOY_PK in chain.env to create a shard slot')
  }
  const n = opts.n ?? Math.min(3, cfg.nodeUrls.length)
  const k = opts.k ?? Math.min(2, n)
  const writer = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as `0x${string}`, chainId: cfg.chainId})
  const {slotId, ruleSalt} = await writer.createSlot({dcqlRule: SLOT_DCQL_RULE, k, n, mode: 'bls', exportable: true})

  // A fresh slot answers /public 200 before its key exists, so wait for the group key itself.
  let committee: string[] = []
  let mpkHex = ''
  const deadline = Date.now() + (opts.timeoutMs ?? 180_000)
  while (Date.now() < deadline) {
    committee = []
    for (const url of cfg.nodeUrls) {
      try {
        const res = await fetch(`${url}/v1/keys/${slotId}/public`, {signal: AbortSignal.timeout(3000)})
        const key = res.ok ? ((await res.json()) as {group_public_key?: string}).group_public_key : undefined
        if (key) {
          committee.push(url)
          if (!mpkHex) mpkHex = key
        }
      } catch {
        /* node busy */
      }
    }
    if (committee.length >= n) break
    await new Promise(r => setTimeout(r, 2000))
  }
  if (committee.length < k) throw new Error(`shard slot ${slotId}: DKG incomplete (keyed committee=${committee.length})`)

  const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, provisionJwt)
  if (!prov.ok) throw new Error(`shard slot ${slotId}: rule provisioning refused — ${prov.errors.join('; ')}`)
  return {slotId, committee, mpkHex}
}

/**
 * Map an on-chain node/verifier `url` (in-cluster Docker DNS, e.g.
 * `http://tasra-node-7:8080`) to the host-published port the demo fleet exposes
 * (`http://localhost:8097`) — so a test running on the HOST can reach an endpoint it
 * discovered from chain. Node N → 8090+N (`:8080` internal), verifier N → 8180+N
 * (`:8081` internal). An unrecognised host is returned unchanged (already reachable, or
 * a different topology). Override the scheme via TASRA_NODE_URLS/TASRA_VERIFIER_URLS upstream.
 */
export function clusterToHost(url: string): string {
  const v = url.match(/keykeeper-verifier-(\d+)/)
  if (v) return `http://localhost:${8180 + Number(v[1])}`
  const n = url.match(/tasra-node-(\d+)/)
  if (n) return `http://localhost:${8090 + Number(n[1])}`
  return url
}
