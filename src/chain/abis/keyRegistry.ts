// Vendored ABI. Do not edit by hand — refresh the whole file from the contract
// artifacts (a manual step; see CONTRIBUTING.md).
// Source: contracts/out/KeyRegistry.sol/KeyRegistry.json (`abi` field).

export const keyRegistryAbi = [
  {
    "type": "constructor",
    "inputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "BPS_DENOMINATOR",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "COMMIT_GAP",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "LEASE_DURATION",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "MAX_DUAL_APPROVERS",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "MAX_EPOCH_SKIP",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "MAX_N",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "MAX_VERIFIER_COMMITTEE",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "MIN_RULE_TIMELOCK",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "PK_ATTEST_DOMAIN",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "RESHARE_ATTEST_DOMAIN",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "REVEAL_WINDOW",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ROTATE_ATTEST_DOMAIN",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "RULE_ATTEST_DOMAIN",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "UPGRADE_INTERFACE_VERSION",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "acceptOwnership",
    "inputs": [],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "activateRuleUpdate",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "assignedNodes",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address[]",
        "internalType": "address[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "attestRuleAdoption",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleVer",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "attestRuleAdoptionBatch",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleVer",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "sigs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "cancelSlot",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "commitKeySlot",
    "inputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "targetEpoch",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "commitSeedDigest",
    "inputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "computeCommitment",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      },
      {
        "name": "creator",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "pure"
  },
  {
    "type": "function",
    "name": "createKeySlot",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createKeySlotFiltered",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createKeySlotFilteredExportable",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createKeySlotFilteredWithPolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      },
      {
        "name": "policy",
        "type": "tuple",
        "internalType": "struct KeyRegistry.RulePolicy",
        "components": [
          {
            "name": "admin",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "guardian",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "timelock",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "dualControlApprovers",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "dualControlPolicy",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "ruleHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "endorseRuleUpdate",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getKeySlot",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct KeyRegistry.KeySlot",
        "components": [
          {
            "name": "creator",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "ruleCommitment",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "threshold",
            "type": "tuple",
            "internalType": "struct KeyRegistry.Threshold",
            "components": [
              {
                "name": "k",
                "type": "uint16",
                "internalType": "uint16"
              },
              {
                "name": "n",
                "type": "uint16",
                "internalType": "uint16"
              }
            ]
          },
          {
            "name": "mode",
            "type": "uint8",
            "internalType": "enum KeyRegistry.Mode"
          },
          {
            "name": "publicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "epoch",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "committeeVersion",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "exists",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "cancelled",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "expiry",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "ruleVersion",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "auth",
            "type": "uint8",
            "internalType": "enum KeyRegistry.AuthType"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "registry",
        "type": "address",
        "internalType": "contract NodeRegistry"
      },
      {
        "name": "beacon",
        "type": "address",
        "internalType": "contract IRandomBeacon"
      },
      {
        "name": "owner_",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "isTrustedForwarder",
    "inputs": [
      {
        "name": "forwarder",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "keyExportEnabled",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "minCommitteeStake",
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
    "type": "function",
    "name": "nodeRegistry",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract NodeRegistry"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "owner",
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
    "name": "pendingOwner",
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
    "name": "pendingRule",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "notBefore",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "pkAttestDigest",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "keyHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "proposeRuleUpdate",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "newRuleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "proxiableUUID",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "randomBeacon",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract IRandomBeacon"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "renew",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "renounceOwnership",
    "inputs": [],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "requireCommitReveal",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "reshareAttestDigest",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "committeeVersion",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "payloadHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "reshareKey",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "newOperators",
        "type": "address[]",
        "internalType": "address[]"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "reason",
        "type": "string",
        "internalType": "string"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "reshareKeyAttested",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "newOperators",
        "type": "address[]",
        "internalType": "address[]"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "reason",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "sigs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revealKeySlot",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revealKeySlotWithPolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      },
      {
        "name": "policy",
        "type": "tuple",
        "internalType": "struct KeyRegistry.RulePolicy",
        "components": [
          {
            "name": "admin",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "guardian",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "timelock",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revealKeySlotWithSeed",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      },
      {
        "name": "seedSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revealKeySlotWithSeedAndPolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "auth",
        "type": "uint8",
        "internalType": "enum KeyRegistry.AuthType"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "requiredTags",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      },
      {
        "name": "seedSig",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "policy",
        "type": "tuple",
        "internalType": "struct KeyRegistry.RulePolicy",
        "components": [
          {
            "name": "admin",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "guardian",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "timelock",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "rotateAttestDigest",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "reasonHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "rotateKey",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "string",
        "internalType": "string"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "rotateKeyAttested",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "sigs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "ruleAdoptAttestDigest",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ruleAdoptionThreshold",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ruleAdoptionVotes",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "rulePolicy",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "admin",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "guardian",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "timelock",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "setDualControlPolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "ruleHash",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "approvers",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setMinCommitteeStake",
    "inputs": [
      {
        "name": "minStake",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setRequireCommitReveal",
    "inputs": [
      {
        "name": "required",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setRulePolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "admin",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "guardian",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "timelock",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setTrustedForwarder",
    "inputs": [
      {
        "name": "forwarder",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setVerifierPolicy",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "committee",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "slotCommits",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "targetEpoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "expiryEpoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "creator",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "used",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "submitPublicKey",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "publicKey",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "attestation",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "submitPublicKeyAttested",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "publicKey",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "sigs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "transferOwnership",
    "inputs": [
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "trustedForwarder",
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
    "name": "upgradeToAndCall",
    "inputs": [
      {
        "name": "newImplementation",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "verifierPolicy",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "committee",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "version",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
      }
    ],
    "stateMutability": "pure"
  },
  {
    "type": "function",
    "name": "vetoRuleUpdate",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "DualControlPolicySet",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      },
      {
        "name": "ruleHash",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "approvers",
        "type": "bytes32[]",
        "indexed": false,
        "internalType": "bytes32[]"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "FilteredSelection",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "candidatePool",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "n",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Initialized",
    "inputs": [
      {
        "name": "version",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "KeyExportEnabled",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "KeySlotCreated",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "creator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "threshold",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct KeyRegistry.Threshold",
        "components": [
          {
            "name": "k",
            "type": "uint16",
            "internalType": "uint16"
          },
          {
            "name": "n",
            "type": "uint16",
            "internalType": "uint16"
          }
        ]
      },
      {
        "name": "mode",
        "type": "uint8",
        "indexed": false,
        "internalType": "enum KeyRegistry.Mode"
      },
      {
        "name": "assigned",
        "type": "address[]",
        "indexed": false,
        "internalType": "address[]"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "MinCommitteeStakeSet",
    "inputs": [
      {
        "name": "minStake",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnershipTransferStarted",
    "inputs": [
      {
        "name": "previousOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "newOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnershipTransferred",
    "inputs": [
      {
        "name": "previousOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "newOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "PublicKeyAttested",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "operator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "keyHash",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "votes",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "PublicKeyUpdated",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "publicKey",
        "type": "bytes",
        "indexed": false,
        "internalType": "bytes"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "attestation",
        "type": "bytes",
        "indexed": false,
        "internalType": "bytes"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RequireCommitRevealSet",
    "inputs": [
      {
        "name": "required",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ReshareRequired",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "committeeVersion",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "threshold",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct KeyRegistry.Threshold",
        "components": [
          {
            "name": "k",
            "type": "uint16",
            "internalType": "uint16"
          },
          {
            "name": "n",
            "type": "uint16",
            "internalType": "uint16"
          }
        ]
      },
      {
        "name": "newAssigned",
        "type": "address[]",
        "indexed": false,
        "internalType": "address[]"
      },
      {
        "name": "reason",
        "type": "string",
        "indexed": false,
        "internalType": "string"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ReshareVoted",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "committeeVersion",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "operator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "payloadHash",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "votes",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RotationRequired",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "string",
        "indexed": false,
        "internalType": "string"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RotationVoted",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "epoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "operator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "votes",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RuleActivated",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "indexed": true,
        "internalType": "uint64"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RuleAdoptionAttested",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "indexed": true,
        "internalType": "uint64"
      },
      {
        "name": "operator",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "ruleCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "votes",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RulePolicySet",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "admin",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "guardian",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "timelock",
        "type": "uint32",
        "indexed": false,
        "internalType": "uint32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RuleUpdateEndorsed",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "indexed": true,
        "internalType": "uint64"
      },
      {
        "name": "notBefore",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RuleUpdateProposed",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "indexed": true,
        "internalType": "uint64"
      },
      {
        "name": "newRuleCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "notBefore",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RuleUpdateVetoed",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "version",
        "type": "uint64",
        "indexed": true,
        "internalType": "uint64"
      },
      {
        "name": "guardian",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SlotCancelled",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "creator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "refund",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "penalty",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SlotCommitted",
    "inputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "creator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "targetEpoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SlotRenewed",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "fee",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "newExpiry",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SlotRevealed",
    "inputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "seedEpoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SlotRevealedWithSeed",
    "inputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "TrustedForwarderSet",
    "inputs": [
      {
        "name": "previous",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "forwarder",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Upgraded",
    "inputs": [
      {
        "name": "implementation",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "VerifierPolicySet",
    "inputs": [
      {
        "name": "slotId",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "committee",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "indexed": false,
        "internalType": "uint16"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AddressEmptyCode",
    "inputs": [
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "AlreadyAdopted",
    "inputs": []
  },
  {
    "type": "error",
    "name": "AlreadyAttested",
    "inputs": []
  },
  {
    "type": "error",
    "name": "AlreadyVoted",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadSeedSignature",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BeaconSeedUnavailable",
    "inputs": [
      {
        "name": "targetEpoch",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "CommitAlreadyExists",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitAlreadyUsed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitExpired",
    "inputs": [
      {
        "name": "current",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "expiry",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "CommitMissing",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitRevealRequired",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitRevealUnsupported",
    "inputs": []
  },
  {
    "type": "error",
    "name": "DualControlPolicyAlreadySet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "DuplicateAttestor",
    "inputs": [
      {
        "name": "operator",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "DuplicateOperator",
    "inputs": [
      {
        "name": "operator",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "ECDSAInvalidSignature",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ECDSAInvalidSignatureLength",
    "inputs": [
      {
        "name": "length",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "ECDSAInvalidSignatureS",
    "inputs": [
      {
        "name": "s",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "ERC1967InvalidImplementation",
    "inputs": [
      {
        "name": "implementation",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "ERC1967NonPayable",
    "inputs": []
  },
  {
    "type": "error",
    "name": "EmptyPublicKey",
    "inputs": []
  },
  {
    "type": "error",
    "name": "EpochNotReached",
    "inputs": [
      {
        "name": "current",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "target",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "FailedCall",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InactiveOperator",
    "inputs": [
      {
        "name": "operator",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InsufficientAttestations",
    "inputs": [
      {
        "name": "have",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "need",
        "type": "uint16",
        "internalType": "uint16"
      }
    ]
  },
  {
    "type": "error",
    "name": "InsufficientFilteredPool",
    "inputs": [
      {
        "name": "have",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "need",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InsufficientStakedPool",
    "inputs": [
      {
        "name": "have",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "need",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "minStake",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidDualControlPolicy",
    "inputs": [
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "approvers",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidInitialization",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidRulePolicy",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidThreshold",
    "inputs": [
      {
        "name": "k",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "n",
        "type": "uint16",
        "internalType": "uint16"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidVerifierPolicy",
    "inputs": [
      {
        "name": "committee",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "quorum",
        "type": "uint16",
        "internalType": "uint16"
      }
    ]
  },
  {
    "type": "error",
    "name": "NoPendingRule",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotAssigned",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotCreator",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotInitializing",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotRuleAdmin",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotRuleGuardian",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OwnableInvalidOwner",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "OwnableUnauthorizedAccount",
    "inputs": [
      {
        "name": "account",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "OwnershipRenounceDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PublicKeyAlreadySetForEpoch",
    "inputs": [
      {
        "name": "epoch",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "RuleAdoptionBelowThreshold",
    "inputs": [
      {
        "name": "have",
        "type": "uint16",
        "internalType": "uint16"
      },
      {
        "name": "need",
        "type": "uint16",
        "internalType": "uint16"
      }
    ]
  },
  {
    "type": "error",
    "name": "RuleCommitmentMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RuleImmutable",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RulePolicyAlreadySet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RulePolicySlotNotFresh",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RuleTimelockNotElapsed",
    "inputs": [
      {
        "name": "nowTs",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "notBefore",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "RuleUpdatePending",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RuleVersionMismatch",
    "inputs": [
      {
        "name": "given",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "expected",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "SameRuleHash",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SlotAlreadyExists",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SlotCancelledErr",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SlotMissing",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StaleEpoch",
    "inputs": [
      {
        "name": "submitted",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "current",
        "type": "uint64",
        "internalType": "uint64"
      }
    ]
  },
  {
    "type": "error",
    "name": "ThresholdKeyUnset",
    "inputs": []
  },
  {
    "type": "error",
    "name": "TooFewActiveNodes",
    "inputs": [
      {
        "name": "active",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "needed",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "TooManyAttestations",
    "inputs": [
      {
        "name": "count",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "UUPSUnauthorizedCallContext",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UUPSUnsupportedProxiableUUID",
    "inputs": [
      {
        "name": "slot",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "VerifierPolicyAlreadySet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroCommitment",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroRuleCommitment",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroRuleHash",
    "inputs": []
  }
] as const
