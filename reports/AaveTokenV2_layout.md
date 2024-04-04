| Name                              | Type                                                                                   | Slot | Offset | Bytes | Contract                                       |
| --------------------------------- | -------------------------------------------------------------------------------------- | ---- | ------ | ----- | ---------------------------------------------- |
| \_balances                        | mapping(address => uint256)                                                            | 0    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_allowances                      | mapping(address => mapping(address => uint256))                                        | 1    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_totalSupply                     | uint256                                                                                | 2    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_name                            | string                                                                                 | 3    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_symbol                          | string                                                                                 | 4    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_decimals                        | uint8                                                                                  | 5    | 0      | 1     | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| lastInitializedRevision           | uint256                                                                                | 6    | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| **\_\_**gap                       | uint256[50]                                                                            | 7    | 0      | 1600  | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_nonces                          | mapping(address => uint256)                                                            | 57   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_votingSnapshots                 | mapping(address => mapping(uint256 => struct GovernancePowerDelegationERC20.Snapshot)) | 58   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_votingSnapshotsCounts           | mapping(address => uint256)                                                            | 59   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_aaveGovernance                  | contract ITransferHook                                                                 | 60   | 0      | 20    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| DOMAIN_SEPARATOR                  | bytes32                                                                                | 61   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_votingDelegates                 | mapping(address => address)                                                            | 62   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_propositionPowerSnapshots       | mapping(address => mapping(uint256 => struct GovernancePowerDelegationERC20.Snapshot)) | 63   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_propositionPowerSnapshotsCounts | mapping(address => uint256)                                                            | 64   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
| \_propositionPowerDelegates       | mapping(address => address)                                                            | 65   | 0      | 32    | etherscan/AaveTokenV2/Contract.sol:AaveTokenV2 |
