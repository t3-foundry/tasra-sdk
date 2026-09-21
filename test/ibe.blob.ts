// Identity-scoped envelope encryption for large objects — offline suite over the shipped
// functions: seal → open round trip across many chunks, range decryption, and every way a
// chunk can be wrong (tampered, moved, from another blob, truncated, wrong identity key).
//
// Run: tsx test/ibe.blob.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {ibeCombineExtract} from '../src/crypto/ibe.ts'
import {
  ibeBlobChunkRange,
  ibeBlobDecryptKey,
  ibeBlobDigest,
  ibeDecryptBlobChunk,
  ibeOpenBlob,
  ibeSealBlob,
  ibeUnwrapBlobKey,
} from '../src/crypto/ibe-blob.ts'

let passed = 0
const failures: string[] = []
const ok = (name: string, cond: boolean) => (cond ? passed++ : failures.push(name))
const fails = async (name: string, f: () => Promise<unknown>) => {
  try {
    await f()
    failures.push(`${name} (did not throw)`)
  } catch {
    passed++
  }
}

// A 2-of-3 BLS "slot" built directly: msk = polynomial(0), shares at 1..3, mpk = msk·G2.
// Identity keys come out of the same Lagrange combine the SDK uses against real keepers.
const {Fr} = bls12_381.fields
const G1 = bls12_381.G1.ProjectivePoint
const G2 = bls12_381.G2.ProjectivePoint
const a0 = Fr.create(BigInt('0x1f2e3d4c5b6a79880000000000000000000000000000000000000000000000ab'))
const a1 = Fr.create(BigInt('0x0a0b0c0d0e0f10111213141516171819202122232425262728292a2b2c2d2e2f'))
const share = (i: number) => Fr.add(a0, Fr.mul(a1, BigInt(i)))
const mpk = G2.BASE.multiply(a0).toRawBytes(true)
const vsG2 = new Map([1, 2, 3].map(i => [i, G2.BASE.multiply(share(i)).toRawBytes(true)]))
function skIdFor(identity: string): Uint8Array {
  const qId = G1.fromAffine(bls12_381.G1.hashToCurve(new TextEncoder().encode(identity), {DST: 'keykeeper/BLS12381-BF-IBE-HashToG1-v1'}).toAffine())
  const partials = [1, 2].map(i => ({identifier: i, value: qId.multiply(share(i)).toRawBytes(true)}))
  return ibeCombineExtract(vsG2, partials, new TextEncoder().encode(identity))
}

const identity = 'did:key:z6MkAlice/imaging/2026-09'
const image = new Uint8Array(3 * 4096 + 777) // 4 chunks at 4 KiB, last one partial
for (let i = 0; i < image.length; i++) image[i] = (i * 7 + (i >> 8)) & 255

try {
  const sealed = await ibeSealBlob(mpk, identity, image, {contentType: 'image/png', chunkSize: 4096})
  ok('header: 4 chunks of 4 KiB, size + type recorded', sealed.header.chunkCount === 4 && sealed.header.size === image.length && sealed.header.contentType === 'image/png')
  ok('body length = size + 16 bytes per chunk', sealed.body.length === image.length + 4 * 16)
  ok('body is not the plaintext', !sealed.body.subarray(0, 64).every((b, i) => b === image[i]))

  const skId = skIdFor(identity)
  const opened = await ibeOpenBlob(skId, sealed.header, sealed.body)
  ok('open with the identity key round-trips the whole image', opened.length === image.length && opened.every((b, i) => b === image[i]))

  // Range decryption: chunk 2 alone.
  const dek = ibeUnwrapBlobKey(skId, sealed.header)
  const key = await ibeBlobDecryptKey(dek)
  const r = ibeBlobChunkRange(sealed.header, 2)
  const chunk2 = await ibeDecryptBlobChunk(key, sealed.header, 2, sealed.body.subarray(r.start, r.end))
  ok('a single chunk decrypts from its byte range', chunk2.every((b, i) => b === image[2 * 4096 + i]))
  const last = ibeBlobChunkRange(sealed.header, 3)
  ok('the last range is the partial chunk', last.plainLength === 777 && last.end === sealed.body.length)

  // Wrong identity key: a different identity's sk_ID cannot unwrap.
  await fails('another identity\'s key does not unwrap the data key', async () => ibeUnwrapBlobKey(skIdFor('did:key:z6MkAlice/imaging/2026-10'), sealed.header))
  await fails('a sibling category\'s key does not unwrap either', async () => ibeUnwrapBlobKey(skIdFor('did:key:z6MkAlice/labs/2026-09'), sealed.header))

  // Tampering: flip one byte in chunk 1.
  const tampered = new Uint8Array(sealed.body)
  const flipAt = ibeBlobChunkRange(sealed.header, 1).start + 5
  tampered[flipAt] = (tampered[flipAt] ?? 0) ^ 1
  await fails('a flipped byte fails that chunk', async () => ibeOpenBlob(skId, sealed.header, tampered))

  // Reordering: swap chunks 0 and 1 (same length) — position is in the AAD.
  const swapped = new Uint8Array(sealed.body)
  const r0 = ibeBlobChunkRange(sealed.header, 0)
  const r1 = ibeBlobChunkRange(sealed.header, 1)
  swapped.set(sealed.body.subarray(r1.start, r1.end), r0.start)
  swapped.set(sealed.body.subarray(r0.start, r0.end), r1.start)
  await fails('swapped chunks fail (position bound)', async () => ibeOpenBlob(skId, sealed.header, swapped))

  // Truncation: drop the last chunk and lie in the header — the last-flag is in the AAD.
  const truncated = {...sealed.header, chunkCount: 3, size: 3 * 4096}
  await fails('a truncated blob fails (last flag bound)', async () => ibeOpenBlob(skId, truncated, sealed.body.subarray(0, 3 * (4096 + 16))))

  // Cross-blob: a chunk from another sealed object under the same key material.
  const other = await ibeSealBlob(mpk, identity, image, {chunkSize: 4096})
  const mixed = new Uint8Array(sealed.body)
  mixed.set(other.body.subarray(r0.start, r0.end), r0.start)
  await fails('a chunk from another blob fails (blobId bound)', async () => ibeOpenBlob(skId, sealed.header, mixed))

  // Wrong identity in the header (moving a blob to another patient's namespace) fails the unwrap.
  const moved = {...sealed.header, identity: 'did:key:z6MkBob/imaging/2026-09'}
  await fails('a blob relabelled to another identity does not unwrap', async () => ibeUnwrapBlobKey(skIdFor('did:key:z6MkBob/imaging/2026-09'), moved))

  ok('digest is 32 bytes and stable', ibeBlobDigest(sealed.body).length === 32 && ibeBlobDigest(sealed.body).join() === ibeBlobDigest(new Uint8Array(sealed.body)).join())

  // Tiny + default chunking.
  const tiny = await ibeSealBlob(mpk, identity, new Uint8Array([1, 2, 3]))
  ok('a tiny object is one chunk', tiny.header.chunkCount === 1 && (await ibeOpenBlob(skId, tiny.header, tiny.body)).join() === '1,2,3')
} catch (e) {
  failures.push(`threw: ${e instanceof Error ? e.stack ?? e.message : String(e)}`)
}

if (failures.length > 0) {
  console.error(`✗ ibe.blob: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ ibe.blob: ${passed} checks passed`)
