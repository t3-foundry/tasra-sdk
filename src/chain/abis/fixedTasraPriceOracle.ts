// Vendored ABI. Do not edit by hand — refresh the whole file from the contract
// artifacts (a manual step; see CONTRIBUTING.md).
// Source: contracts/out/FixedTasraPriceOracle.sol/FixedTasraPriceOracle.json (`abi` field).

export const fixedTasraPriceOracleAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "tsraPerEur_",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "eurCentsForTsra",
    "inputs": [
      {
        "name": "tsraAmount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tsraForEurCents",
    "inputs": [
      {
        "name": "eurCents",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tsraPerEur",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "error",
    "name": "ZeroRate",
    "inputs": []
  }
] as const
