// Slot funding — faucet: fund a sovereign account so it can self-create a slot
// on-chain (createTasraWriteClient().createSlot). The managed relayer
// "provisioner" path was removed — nothing used it; every consumer self-signs.
export {httpFaucet} from './faucet.js'
export type {Faucet, FaucetGrant} from './faucet.js'
