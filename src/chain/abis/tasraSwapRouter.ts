// Vendored ABI. Do not edit by hand — refresh the whole file from the contract
// artifacts (a manual step; see CONTRIBUTING.md).
// Source: contracts/out/TasraSwapRouter.sol/TasraSwapRouter.json (`abi` field).

export const tasraSwapRouterAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "v3Router_",
        "type": "address",
        "internalType": "contract ISwapRouter"
      },
      {
        "name": "eurc_",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tsra_",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "poolFee_",
        "type": "uint24",
        "internalType": "uint24"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "buyWithEurc",
    "inputs": [
      {
        "name": "eurcIn",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "minTsraOut",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "tsraOut",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "eurc",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "poolFee",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint24",
        "internalType": "uint24"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tsra",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "v3Router",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract ISwapRouter"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "error",
    "name": "EurcTransferFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddress",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAmount",
    "inputs": []
  }
] as const
