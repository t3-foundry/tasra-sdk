// compound committee authorization — token crypto + HTTP orchestration.
export {
  selectVerifierCommittee,
  compoundTokenCanonicalBytes,
  compoundTokenHash,
  opAttestationHash,
  clientBindingHash,
  verifierLeaf,
  verifyMerkleProof,
  merkleRoot,
  merkleProof,
  verifyCompoundToken,
  assembleCompoundToken,
  decodeCompoundToken,
} from './token.js'
export type {
  TokenType,
  CompoundTokenPayload,
  CommitteeSignature,
  VerifierSet,
  VerifiedToken,
  VerifyCompoundTokenOptions,
  CompoundTokenWire,
  CommitteeSignatureWire,
} from './token.js'
export {
  committeeAuthorize,
  gatherCommitteeToken,
  committeeSign,
  committeeDecrypt,
  CommitteeAuthorizeError,
} from './client.js'
export type {
  CommitteeAuthorizeBody,
  CommitteeAuthorizeReply,
  GatherCommitteeTokenOpts,
  CommitteeSignOpts,
  CommitteeDecryptOpts,
  VerifierProof,
} from './client.js'
export {
  requestCommitteeToken,
  committeeSignRequest,
  committeeDecryptRequest,
  buildVerifierProofs,
  committeeChainReadsFromClient,
  ed25519ClientSigner,
  holderProofPerVerifier,
} from './request.js'
export type {
  CommitteeVerifier,
  CommitteeChainReads,
  HolderProofPerVerifier,
  RequestCommitteeTokenOpts,
  CommitteeTokenResult,
  CommitteeSignRequestOpts,
  CommitteeDecryptRequestOpts,
  ClientSigner,
} from './request.js'


// ─── identity-key extraction ────────────────────────────────────────
export {requestIbeExtractionPartials} from './client.js'
export type {IbeExtractOpts, IbeExtractionPartial} from './client.js'
export {ibeExtractRequest, ibeDecryptRequest} from './request.js'
export type {IbeExtractRequestOpts} from './request.js'

// ─── derived OAuth audience + DPoP htu ────────────────────────────
export {platformAudience, dpopHtu, normalizeOrigin, OAUTH_RESPONSE_PATH} from './oauth.js'
