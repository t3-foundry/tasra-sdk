// OpenID4VP + OpenID4VCI against the Verifier Agent — the wallet contract the platform
// speaks is the one the Hovi Wallet speaks, and this subpath is a clone of that behaviour:
//
//   Wallet:  receiveCredential({offerUri, holder})            → an SD-JWT VC in the wallet
//            presentToRequestUri(openid4vpUri, held, holder)  → JAR verified via did:web, ONE
//                                                               credential bound with a KB-JWT,
//                                                               JWE-encrypted, POSTed
//   verifier-agent/app:  openVerifierAgentSession({verifierAgentUrl, signer: creator, …})        → hand `qrPayload` to the wallet
//            awaitVerifierAgentResult(session)                            → the compound token
//
// The Tasra-specific derivations (`requestHash`, `derivedNonce`) live in `binding` for the verifier-agent
// side and tests; a wallet never interprets the nonce it copies into its KB-JWT.

export * from './binding.js'
export * from './jose.js'
export * from './sd-jwt.js'
export * from './jwe.js'
export * from './did-web.js'
export * from './request-object.js'
export * from './wallet.js'
export * from './oid4vci.js'
export * from './verifier-agent.js'
