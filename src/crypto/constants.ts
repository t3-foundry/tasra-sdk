// Pinned wire-format constants. These values are baked into every encrypted
// message in production. A change to any of them makes existing ciphertexts
// undecryptable — treat them as cryptographic invariants, not refactor targets.
// Each assertion below mirrors the pin tests in the reference envelope implementation
// and the reference KEM implementation.

// Domain-separation tag for the BLS KEM key-derivation and nonce-derivation
// functions. Hashed into the AEAD key for EVERY group-encryption envelope.
// NEVER change after a production rollout — a version bump silently turns
// every encrypted chat message on disk into garbage.
// Mirrors: the reference KEM implementation KEM_DOMAIN = b"BLS12381-ElGamalG2-KEM-v1"
export const KEM_DOMAIN = new TextEncoder().encode('BLS12381-ElGamalG2-KEM-v1')

// Wire-format version byte for the legacy (no-epoch) layout.
export const ENVELOPE_VERSION_V1 = 0x01 as const

// Wire-format version byte for the strict-mode (embedded-epoch) layout.
export const ENVELOPE_VERSION_V2 = 0x02 as const

// Hard cap on identity length (bytes). Mirrors the reference MAX_IDENTITY_LEN.
export const MAX_IDENTITY_LEN = 1024 as const

// Hard cap on AEAD ciphertext length (bytes). Mirrors the reference MAX_AEAD_CT_LEN.
export const MAX_AEAD_CT_LEN = 1_048_576 // 1024 * 1024

// BLS12-381 G2 compressed point width (bytes). Externally fixed by the curve.
export const COMPRESSED_G2_LEN = 96 as const

// ChaCha20-Poly1305 nonce width (bytes). Externally fixed by the cipher.
export const NONCE_LEN = 12 as const

// On-chain slot-id width (bytes32). Fixed by the Ethereum contract.
export const SLOT_ID_LEN = 32 as const

// ─── [KK] envelope-in-text detection (was kk-constants.ts) ───────────────
// Tasra envelope prefix embedded in a transport's message text.
// Clients without the key see the raw prefix + base64; a Tasra-aware
// client replaces it with the decrypted message inline.
export const KK_PREFIX = '[KK]'

// Minimum length of a base64 GroupEnvelope v0x01 (147 bytes overhead → ~196 b64 chars).
export const KK_MIN_B64_LEN = 196
