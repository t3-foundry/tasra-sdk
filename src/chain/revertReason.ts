// Name a revert that viem could not.
//
// viem decodes a custom error only when it knows which ABI the call belongs to. A raw
// `estimateGas` — what the relay path does before asking a relayer to forward a call — carries no
// ABI, so viem reports every custom error as "Execution reverted for an unknown reason." and the
// four bytes that say what actually happened are left inside the error chain. A caller then sees a
// deployment refuse a write with no way to learn why: `createSlot` on a genesis that requires
// commit-reveal reverts `CommitRevealRequired()`, which reads as an unexplained failure.
//
// Every Tasra contract's errors are in `CONTRACT_ABIS`, so the selector can be decoded back
// into the name and arguments the contract meant.

import {decodeErrorResult} from 'viem'
import type {Hex} from 'viem'
import {CONTRACT_ABIS} from './abis/index.js'

/** Every `error` item of every contract this package knows. */
const ERROR_ITEMS = Object.values(CONTRACT_ABIS)
  .flatMap(abi => abi as readonly {type?: string}[])
  .filter(item => item?.type === 'error')

/**
 * The revert data viem kept somewhere in the error's `cause` chain. RPC transports differ on where
 * they put it (`EstimateGasExecutionError` → `ExecutionRevertedError` → `RpcRequestError.data` on
 * an Avalanche C-chain node), so walk the chain rather than guess a shape.
 */
function revertData(error: unknown): Hex | undefined {
  const seen = new Set<unknown>()
  for (let e: unknown = error; e && typeof e === 'object' && !seen.has(e); e = (e as {cause?: unknown}).cause) {
    seen.add(e)
    const data = (e as {data?: unknown}).data
    // A bare selector is 10 characters; anything shorter cannot name an error.
    if (typeof data === 'string' && /^0x[0-9a-fA-F]{8,}$/.test(data)) return data as Hex
  }
  return undefined
}

/**
 * `CommitRevealRequired()`, or `InsufficientFilteredPool(3, 5)`, for an error carrying revert data
 * this package's ABIs can decode; `undefined` when there is no data, or when it belongs to a
 * contract outside them (a token's own error, say). Never throws.
 */
export function describeRevert(error: unknown): string | undefined {
  const data = revertData(error)
  if (!data) return undefined
  try {
    const {errorName, args} = decodeErrorResult({abi: ERROR_ITEMS, data})
    return `${errorName}(${(args ?? []).map(a => String(a)).join(', ')})`
  } catch {
    return undefined
  }
}

/**
 * `prefix`, then the decoded revert when there is one and viem's message when there is not. Keeps
 * the original as `cause`, so a caller that wants the raw error still has it.
 */
export function revertError(error: unknown, prefix: string): Error {
  const named = describeRevert(error)
  const detail = named ?? String((error as Error | undefined)?.message ?? error).slice(0, 240)
  return new Error(`${prefix}: ${detail}`, {cause: error})
}
