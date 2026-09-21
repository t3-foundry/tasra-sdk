// Key material from the node fleet: the group public key and k-of-n shard
// assembly. The session built on top of these lives in `client/` (the managed
// `Session`); there is no channel-shaped layer any more.
export {fetchAndAssembleKey, fetchMpk} from './node-client.js'
