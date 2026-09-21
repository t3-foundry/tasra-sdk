// tasra-sdk — a TypeScript access gate that exposes the full functionality
// of a Tasra Network (keykeeper-node + verifier + contracts) to developers.
//
// Two layers, both product-agnostic:
//   • A high-level managed client — `createTasraClient(...).openSession(slot, auth)`
//     returns a Session that holds the JWT + assembled key, auto-renews on
//     expiry, re-assembles on rotation, and exposes encrypt/decrypt/sign/close.
//   • The underlying composable primitives — fetch BLS shards from k-of-n
//     keykeeper-nodes and Lagrange-assemble the master secret key in-process
//     (the nodes never reveal it), redeem/refresh DCQL-gated JWTs, assemble
//     compound committee authorization tokens, encrypt/decrypt message envelopes
//     (ChaCha20-Poly1305 over BLS-G2 ElGamal), create slots (sovereign or
//     relayer), and read/write on-chain state (see the `tasra-sdk/chain`
//     subpath export).
//
// What this SDK is NOT: a product. It has no knowledge of any specific
// transport, messaging shape, or application — a developer composes these on top.

// ─── Managed Client + Session (the few-lines integration surface) ───────
export {createTasraClient} from './client/index.js'
export type {
  TasraClient,
  TasraClientConfig,
  Session,
  SessionAuth,
  VpJwtAuth,
  HolderProofAuth,
  OpenSessionOpts,
  SignOpts,
} from './client/index.js'

// ─── Crypto primitives ─────────────────────────────────────────────────
export {encryptEnvelope, toBytes, fromBytes} from './crypto/index.js'
export {decryptWithMasterKey} from './crypto/index.js'

// ─── Envelope detection in transport payloads ──────────────────────────
export {buildTasraText, parseTasraPost, isTasraPost, MAX_PLAINTEXT_LEN} from './crypto/index.js'

// ─── Node client ────────────────────────────────────────────────────────
export {fetchAndAssembleKey, fetchMpk} from './keys/index.js'

// ─── Signing ──────────────────────────────────────────────────────────────
// FROST-Ed25519 (custody one-shot + client-coordinated shard-delivery, with
// local aggregation/verification) and threshold ECDSA for EVM EOAs.
export {
  signCustody,
  signWithShardDelivery,
  signUserRequest,
  userSignaturePayload,
} from './signing/index.js'
export type {SignCustodyOpts, FrostSignResult, ShardSignOpts} from './signing/index.js'
export {
  aggregate as aggregateFrostSignature,
  verify as verifyFrostSignature,
} from './crypto/index.js'
export type {FrostSignature, FrostCommitment, FrostShare} from './crypto/index.js'
export {signEoaDigest, ethSignatureV, addressFromEoaPubkey} from './signing/index.js'
export type {EoaSignOpts, EoaSignature} from './signing/index.js'

// ─── Decryption (BLS threshold) ─────────────────────────────────────────────
// Custody (node-coordinated) and shard-delivery (client combines partial G2
// decryption shares without ever assembling the master key).
export {decryptCustody, decryptWithShardDelivery} from './decryption/index.js'
export type {DecryptCustodyOpts, ShardDecryptOpts, BlsPeer} from './decryption/index.js'
export {combineDecryptShares, verifyDecryptShare} from './crypto/index.js'
export type {DecryptShare, Ciphertext} from './crypto/index.js'

// ─── Slots: faucet — fund a sovereign account so it can self-create a slot ────
export {httpFaucet} from './slots/index.js'
export type {Faucet, FaucetGrant} from './slots/index.js'

// ─── Errors ───────────────────────────────────────────────────────────
// Branch on the type instead of regexing `err.message`. Every error the SDK
// throws deliberately extends TasraError; `retryable` is the coarse signal
// for callers that don't want to enumerate types.
//
//   catch (e) {
//     if (isAuthDenied(e)) return reclaim()          // 401/403 — never retry
//     if (e instanceof ThresholdNotMetError) …       // e.got / e.need / e.reasons
//     if (isRetryable(e)) return backoffAndRetry()
//   }
export {
  TasraError,
  TasraHttpError,
  AuthDeniedError,
  NodeUnreachableError,
  ThresholdNotMetError,
  SlotRotatedError,
  isAuthDenied,
  isRetryable,
} from './errors.js'
// The committee flow's HTTP error lives with the committee code but is caught
// by consumers of the managed clients, so it is reachable from the main entry.
export {CommitteeAuthorizeError} from './committee/index.js'

// ─── Utils ────────────────────────────────────────────────────────────
export {hexToBytes} from './crypto/index.js'

// ─── DCQL policy grammar (OID4VP-DCQL) ───────────────────────
// The OpenID Foundation's Digital Credentials Query Language. The rule IS the
// wallet request — no compiler between the policy of record and what the user
// is shown. Validate a rule before paying for a slot, or evaluate whether
// credentials satisfy a rule client-side.
export {
  validate as validateDcql,
  evaluate as evaluateDcql,
  select as selectDcql,
  canonicalize as canonicalizeDcql,
  isOid4vpRule,
  jsonCredential,
  FORMAT_JWT_VC_JSON,
  DcqlMalformedError,
  MAX_RULE_LEN as DCQL_MAX_RULE_LEN,
} from './auth/index.js'
export type {
  Query as DcqlQuery,
  CredentialQuery as DcqlCredentialQuery,
  CredentialSetQuery as DcqlCredentialSetQuery,
  ClaimQuery as DcqlClaimQuery,
  Meta as DcqlMeta,
  CredentialView,
  ClaimResult,
  Selection as DcqlSelection,
} from './auth/index.js'

// ─── identity-scoped rules (WHO + WHICH) ───────────────────────
export {
  evaluateIdentityScoped,
  scopeCovers,
  MAX_IDENTITY_LEN,
  type ScopeNamespace,
} from './auth/index.js'

// ─── Recipient-side DCQL access gate (platform-blind) ───────────────────
// A recipient decides LOCALLY whether their held credentials satisfy a slot's
// rule — no query reaches the platform. Pure; reuses the shared evaluator.
export {
  RecipientStore,
  canAccess,
  validateRule as validateRecipientRule,
  type HeldCredential,
} from './recipient/store.js'

// ─── Verifier auth + JWT helpers (agnostic) ─────────────────────────────
// Obtain/refresh a DCQL-gated JWT and inspect it client-side. Pure HTTP/JSON;
// no product or transport assumptions.
export {
  redeemRenewalToken,
  createRenewal,
  revokeRenewal,
  redeemCredential,
  issueAdminCredential,
  revokeSlotUser,
  verifyPresentation,
  verifyVpJwt,
  decodeJwtClaims,
  jwtExpMs,
  isJwtExpiringSoon,
} from './auth/index.js'
export type {RenewalGrant} from './auth/index.js'
export type {IssuedToken, JwtClaims, RedemptionGrant} from './auth/index.js'
// F1/F4 holder proof-of-possession (for verifiers with require_holder_binding).
export {
  credentialsCommitment,
  fetchHolderNonce,
  buildHolderProof,
  createHolderProof,
  ed25519DidKey,
} from './auth/index.js'
export type {HolderSigner, HolderNonce, BuildHolderProofOpts} from './auth/index.js'

// ─── identity-scoped encryption + extraction ───────────────────
// Encrypt offline to an identity under a slot's MPK (`ibeEncrypt` — permissionless, the
// key need not exist yet); read back via `ibeDecryptRequest` (token → k extraction
// partials → verify each → combine → decrypt; `sk_ID` never surfaces) or opt into
// custody with `ibeExtractRequest` (returns `sk_ID` — durable for that identity;
// zeroize when done).
export {
  ibeExtractRequest,
  ibeDecryptRequest,
  requestIbeExtractionPartials,
} from './committee/index.js'
export type {IbeExtractRequestOpts, IbeExtractOpts, IbeExtractionPartial} from './committee/index.js'
export {
  ibeEncrypt,
  ibeVerifyShare,
  ibeCombineExtract,
  ibeCombineDecrypt,
  ibeDecryptWithKey,
} from './crypto/index.js'
export type {IbeCiphertext, IbeDecryptionShare, IbeVerifyingShares} from './crypto/index.js'
// Large objects (images, scans, documents): a per-object data key IBE-wrapped to the
// identity, the body as independently decryptable AES-256-GCM chunks (WebCrypto). One
// extracted `sk_ID` opens every object under that identity; the unwrap is one pairing
// whatever the size.
export {
  ibeSealBlob,
  ibeOpenBlob,
  ibeUnwrapBlobKey,
  ibeBlobDecryptKey,
  ibeDecryptBlobChunk,
  ibeBlobChunkRange,
  ibeBlobWrappedKey,
  ibeBlobDigest,
  IBE_BLOB_DEFAULT_CHUNK,
} from './crypto/index.js'
export type {IbeBlobHeader, SealedBlob} from './crypto/index.js'

// ─── Verifier Agent (OID4VP relay) ─────────────────────────────────
export {
  createOid4vpSession,
  pollOid4vpSession,
  waitForSession,
  payloadDigest,
  VerifierAgentSessionError,
  // The OAuth (BYO-IdP) session kind.
  createOauthSession,
  submitOauthResponse,
} from './verifier-agent/index.js'
export type {
  VerifierAgentSessionErrorKind,
  PresentationOperation,
  PresentationDelegation,
  CreateSessionParams,
  CreateSessionResult,
  CreateOauthSessionResult,
  SessionStatusResult,
} from './verifier-agent/index.js'

// ─── DPoP (RFC 9449) ──────────────────────────
export {
  createDpopKey,
  auth0DpopSigner,
  jwkThumbprint,
  accessTokenHash,
  isHeaderSafeNonce,
} from './auth/dpop.js'
export type {DpopSigner, DpopKey} from './auth/dpop.js'

// ─── Types ──────────────────────────────────────────────────────────────
export type {GroupEnvelope} from './crypto/index.js'
