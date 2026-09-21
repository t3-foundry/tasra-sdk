// Vendored ABI. Do not edit by hand — refresh the whole file from the contract
// artifacts (a manual step; see CONTRIBUTING.md).

import {nodeRegistryAbi} from './nodeRegistry.js'
import {keyRegistryAbi} from './keyRegistry.js'
import {serviceRegistryAbi} from './serviceRegistry.js'
import {settlementAbi} from './settlement.js'
import {tasraTokenAbi} from './tasraToken.js'
import {bondingCurveAbi} from './bondingCurve.js'
import {tasraSwapRouterAbi} from './tasraSwapRouter.js'
import {treasuryAbi} from './treasury.js'
import {tasraVestingVaultAbi} from './tasraVestingVault.js'
import {thresholdRandomBeaconAbi} from './thresholdRandomBeacon.js'
import {prevrandaoSaltBeaconAbi} from './prevrandaoSaltBeacon.js'
import {equivocationSlasherAbi} from './equivocationSlasher.js'
import {platformExecutorAbi} from './platformExecutor.js'
import {fixedTasraPriceOracleAbi} from './fixedTasraPriceOracle.js'
import {mockEurcAbi} from './mockEurc.js'
import {accountantSlashingAbi} from './accountantSlashing.js'
import {livenessRegistryAbi} from './livenessRegistry.js'
import {verifierSetRegistryAbi} from './verifierSetRegistry.js'
import {accountantSetRegistryAbi} from './accountantSetRegistry.js'
import {keeperShareRegistryAbi} from './keeperShareRegistry.js'

export {nodeRegistryAbi} from './nodeRegistry.js'
export {keyRegistryAbi} from './keyRegistry.js'
export {serviceRegistryAbi} from './serviceRegistry.js'
export {settlementAbi} from './settlement.js'
export {tasraTokenAbi} from './tasraToken.js'
export {bondingCurveAbi} from './bondingCurve.js'
export {tasraSwapRouterAbi} from './tasraSwapRouter.js'
export {treasuryAbi} from './treasury.js'
export {tasraVestingVaultAbi} from './tasraVestingVault.js'
export {thresholdRandomBeaconAbi} from './thresholdRandomBeacon.js'
export {prevrandaoSaltBeaconAbi} from './prevrandaoSaltBeacon.js'
export {equivocationSlasherAbi} from './equivocationSlasher.js'
export {platformExecutorAbi} from './platformExecutor.js'
export {fixedTasraPriceOracleAbi} from './fixedTasraPriceOracle.js'
export {mockEurcAbi} from './mockEurc.js'
export {accountantSlashingAbi} from './accountantSlashing.js'
export {livenessRegistryAbi} from './livenessRegistry.js'
export {verifierSetRegistryAbi} from './verifierSetRegistry.js'
export {accountantSetRegistryAbi} from './accountantSetRegistry.js'
export {keeperShareRegistryAbi} from './keeperShareRegistry.js'

/** Contract name → ABI. Keys match Foundry artifact names. */
export const CONTRACT_ABIS = {
  NodeRegistry: nodeRegistryAbi,
  KeyRegistry: keyRegistryAbi,
  ServiceRegistry: serviceRegistryAbi,
  Settlement: settlementAbi,
  TasraToken: tasraTokenAbi,
  BondingCurve: bondingCurveAbi,
  TasraSwapRouter: tasraSwapRouterAbi,
  Treasury: treasuryAbi,
  TasraVestingVault: tasraVestingVaultAbi,
  ThresholdRandomBeacon: thresholdRandomBeaconAbi,
  PrevrandaoSaltBeacon: prevrandaoSaltBeaconAbi,
  EquivocationSlasher: equivocationSlasherAbi,
  PlatformExecutor: platformExecutorAbi,
  FixedTasraPriceOracle: fixedTasraPriceOracleAbi,
  MockEurc: mockEurcAbi,
  AccountantSlashing: accountantSlashingAbi,
  LivenessRegistry: livenessRegistryAbi,
  VerifierSetRegistry: verifierSetRegistryAbi,
  AccountantSetRegistry: accountantSetRegistryAbi,
  KeeperShareRegistry: keeperShareRegistryAbi,
} as const

export type ContractName = keyof typeof CONTRACT_ABIS
