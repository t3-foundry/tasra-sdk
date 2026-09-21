import {fromBytes, type GroupEnvelope} from './envelope.js'
import {base64Decode, base64Encode} from './envelope.js'
import {KK_MIN_B64_LEN, KK_PREFIX} from './constants.js'

// Returns true when the post text carries a Tasra encrypted envelope.
export function isTasraPost(text: string): boolean {
  return (
    text.startsWith(KK_PREFIX) &&
    text.length >= KK_PREFIX.length + KK_MIN_B64_LEN
  )
}

// Extract the base64 envelope string from a Tasra post text.
export function extractEnvelopeB64(text: string): string {
  return text.slice(KK_PREFIX.length)
}

// Parse the envelope from a Tasra post text. Returns null on malformed input.
export function parseTasraPost(text: string): GroupEnvelope | null {
  if (!isTasraPost(text)) return null
  try {
    const b64 = extractEnvelopeB64(text)
    const bytes = base64Decode(b64)
    return fromBytes(bytes)
  } catch {
    return null
  }
}

// Build the post text for an encrypted message.
export function buildTasraText(envelopeBytes: Uint8Array): string {
  return `${KK_PREFIX}${base64Encode(envelopeBytes)}`
}
