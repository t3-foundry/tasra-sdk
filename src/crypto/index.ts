// Pure cryptographic primitives — NO network I/O. BLS KEM + envelope wire format,
// FROST-Ed25519 signature aggregation, [KK] envelope detection, hex helpers.
export {encryptEnvelope, toBytes, fromBytes, MAX_PLAINTEXT_LEN} from './envelope.js'
export type {GroupEnvelope} from './envelope.js'
export {decryptWithMasterKey, combineDecryptShares, verifyDecryptShare} from './kem.js'
export type {DecryptShare, Ciphertext} from './kem.js'
// BF-IBE: real identity-bound encryption (pairing-level), not the KEM above.
export {
  ibeEncrypt,
  ibeVerifyShare,
  ibeCombineExtract,
  ibeCombineDecrypt,
  ibeDecryptWithKey,
  IBE_DOMAIN,
  IBE_HASH_DST,
} from './ibe.js'
export type {IbeCiphertext, IbeDecryptionShare, IbeVerifyingShares} from './ibe.js'
export {buildTasraText, parseTasraPost, isTasraPost} from './detect.js'
export {hexToBytes} from './hex.js'
export {aggregate, verify} from './frost.js'
export type {FrostSignature, FrostCommitment, FrostShare} from './frost.js'

// Identity-scoped envelope encryption for large objects (images, scans): IBE-wrapped data key
// + chunked AES-256-GCM body (WebCrypto).
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
} from './ibe-blob.js'
export type {IbeBlobHeader, SealedBlob} from './ibe-blob.js'
