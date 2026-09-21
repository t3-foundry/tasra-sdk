// Managed Client + Session — the high-level, few-lines integration surface.
export {createTasraClient} from './client.js'
export type {
  TasraClient,
  TasraClientConfig,
  SessionAuth,
  VpJwtAuth,
  HolderProofAuth,
  OpenSessionOpts,
} from './client.js'
export type {Session, SignOpts} from './session.js'
