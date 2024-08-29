## [L-01] `eth_sign` Messages Should Include `len(message)` and Full Message, Not Hash

The current implementation does not adhere to the format specified in EIP 191 for `eth_sign` messages. According to EIP 191, the signed message should be prefixed with the length of the message followed by the message itself, not the hash of the message.

In the provided code, `keccak256` is used to hash the message, which is not compliant with the EIP 191 standard. The correct format should be to include the length of the message and the full message after the prefix.


```solidity

    function _validateProof(bytes32 dataHash, Proof calldata proof) internal view returns (bool isLatestSigners) {
        BaseWeightedMultisigStorage storage slot = _baseWeightedMultisigStorage();

        WeightedSigners calldata signers = proof.signers;

@>>        bytes32 signersHash = keccak256(abi.encode(signers));
        uint256 signerEpoch = slot.epochBySignerHash[signersHash];
        uint256 currentEpoch = slot.epoch;

        isLatestSigners = signerEpoch == currentEpoch;

        if (signerEpoch == 0 || currentEpoch - signerEpoch > previousSignersRetention) revert InvalidSigners();

@>>        bytes32 messageHash = messageHashToSign(signersHash, dataHash);

        _validateSignatures(messageHash, signers, proof.signatures);
    }

```

```solidity
function messageHashToSign(bytes32 signersHash, bytes32 dataHash) public view returns (bytes32) {
    // 96 is the length of the trailing bytes
    return keccak256(bytes.concat('\x19Ethereum Signed Message:\n96', domainSeparator, signersHash, dataHash));
}
```

**Recommendation:**  
To comply with EIP 191, encode the data using the following approach:

```solidity
bytes32 signersHash = len(abi.encode(signers));
```


## [L-02] The `domainSeparator` is initialized in the constructor and is immutable

It was identified that the `domainSeparator` is generated and cached in the `initialize()` function of the `AxelarAmplifierGateway` contract. Once set, it cannot be changed later if the chain is forked. This setup poses a significant security risk: an attacker could potentially reuse valid signatures of the `permit` function on both chains if a chain fork occurs.


```solidity
/**
 * @dev Initializes the contract.
 * @param previousSignersRetention_ The number of previous signers to retain
 * @param domainSeparator_ The domain separator for the signer proof
 * @param minimumRotationDelay_ The minimum delay required between rotations
 */
constructor(
    uint256 previousSignersRetention_,
    bytes32 domainSeparator_,
    uint256 minimumRotationDelay_
) BaseWeightedMultisig(previousSignersRetention_, domainSeparator_, minimumRotationDelay_) {}
```

The immutability of the `domainSeparator` means that if a chain is forked, the same domain separator could be used on both the original and forked chains. This could enable an attacker to exploit valid signatures for token transfers across both chains, potentially leading to unauthorized transactions or token theft.

Consider implementing a mechanism to update or manage the `domainSeparator` dynamically or through a secure governance process. This could involve adding functionality to modify the `domainSeparator` in a controlled manner or using different domain separators for different chains to prevent signature reuse across forks. Ensure that any changes do not compromise the security or integrity of the signature validation process.

## [L-03] Unexpected Underflow When `signerEpoch` is Greater Than `currentEpoch`

The `_validateProof` function may experience an unexpected underflow if `signerEpoch` is greater than `currentEpoch`. The current implementation does not account for this scenario and could lead to unintended transaction reversion.


```solidity
function _validateProof(bytes32 dataHash, Proof calldata proof) internal view returns (bool isLatestSigners) {
    BaseWeightedMultisigStorage storage slot = _baseWeightedMultisigStorage();

    WeightedSigners calldata signers = proof.signers;

    bytes32 signersHash = keccak256(abi.encode(signers));
    uint256 signerEpoch = slot.epochBySignerHash[signersHash];
    uint256 currentEpoch = slot.epoch;

    isLatestSigners = signerEpoch == currentEpoch;

    if (signerEpoch == 0 || currentEpoch - signerEpoch > previousSignersRetention) revert InvalidSigners();

    bytes32 messageHash = messageHashToSign(signersHash, dataHash);

    _validateSignatures(messageHash, signers, proof.signatures);
}
```

The condition `currentEpoch - signerEpoch > previousSignersRetention` can lead to an underflow if `signerEpoch` is greater than `currentEpoch`. In Solidity, subtracting a larger number from a smaller one will result in an underflow, which could cause unintended behavior and incorrect reversion of transactions.

To avoid this underflow, update the condition to handle cases where `signerEpoch` is greater than `currentEpoch`. For example:

```solidity
if (signerEpoch == 0 || currentEpoch < signerEpoch || currentEpoch - signerEpoch > previousSignersRetention) revert InvalidSigners();
```

## [L-04] Inconsistent Message Hash Calculation in `BaseAmplifierGateway`


The `BaseAmplifierGateway` contract demonstrates inconsistent message hash calculations between the `_approveMessage` and `_validateMessage` functions. Specifically, `_approveMessage` uses `message.contractAddress` while `_validateMessage` uses `msg.sender`. This discrepancy can cause valid messages to be rejected due to mismatched hash values.


**1. Inconsistent Parameter Usage:**

- **`_approveMessage` function:**
  - Uses `message.contractAddress` to calculate the message hash.
  - Code Snippet:
    ```solidity
    bytes32 messageHash = _messageHash(
        commandId,
        message.sourceChain,
        message.sourceAddress,
        message.contractAddress,  // Using message.contractAddress here
        message.payloadHash
    );
    ```

- **`_validateMessage` function:**
  - Uses `msg.sender` instead of `message.contractAddress` for the hash calculation.
  - Code Snippet:
    ```solidity
    bytes32 messageHash = _messageHash(
        commandId,
        sourceChain,
        sourceAddress,
        msg.sender,  // Using msg.sender here
        payloadHash
    );
    ```

- The hash value generated in `_approveMessage` will not match the hash generated in `_validateMessage` due to the use of different addresses.
- This mismatch causes the `valid` flag in `_validateMessage` to be false, leading to legitimate messages being rejected.


## [L-05] Inconsistent return type in `execute_message`

In `interchain-token-service/src/contract/execute.rs` the `execute_message` function, the `apply_balance_tracking` function is called to handle balance updates for interchain transfers and token deployments. However, the `apply_balance_tracking` function returns a `Result<(), Error>` type, which means it can return an error. If an error occurs during balance tracking, the `execute_message` function will not propagate the error and will instead proceed with message forwarding. This could lead to inconsistent token balances or other issues.

To address this issue, modify the `execute_message` function to handle errors returned by the `apply_balance_tracking` function. You can do this by using the `?` operator:

```rust
apply_balance_tracking(
    deps.storage,
    source_chain.clone(),
    destination_chain.clone(),
    &its_message,
)?;
```
## [L-06] Missing Check-Effects-Interactions Pattern in `takeToken` Function

The `takeToken` function in the contract does not follow the check-effects-interactions pattern, which increases the risk of a reentrancy attack.


```solidity
    function takeToken(
        bytes32 tokenId,
        bool tokenOnly,
        address from,
        uint256 amount
    ) external payable returns (uint256, string memory symbol) {
        address tokenManager = _create3Address(tokenId);
        (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

        if (tokenOnly && msg.sender != tokenAddress) revert NotToken(msg.sender, tokenAddress);

        if (tokenManagerType == uint256(TokenManagerType.NATIVE_INTERCHAIN_TOKEN)) {
            _takeInterchainToken(tokenAddress, from, amount);
        } else if (tokenManagerType == uint256(TokenManagerType.MINT_BURN)) {
            _burnToken(tokenManager, tokenAddress, from, amount);
        } else if (tokenManagerType == uint256(TokenManagerType.MINT_BURN_FROM)) {
            _burnTokenFrom(tokenAddress, from, amount);
        } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
            _transferTokenFrom(tokenAddress, from, tokenManager, amount);
        } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK_FEE)) {
            amount = _transferTokenFromWithFee(tokenAddress, from, tokenManager, amount);
        } else if (tokenManagerType == uint256(TokenManagerType.GATEWAY)) {
            symbol = IERC20Named(tokenAddress).symbol();
            _transferTokenFrom(tokenAddress, from, address(this), amount);
        } else {
            revert UnsupportedTokenManagerType(tokenManagerType);
        }

        /// @dev Track the flow amount being sent out as a message
@>        ITokenManager(tokenManager).addFlowOut(amount);

        return (amount, symbol);
    }
```

Follow the check-effects-interactions pattern by updating the internal state before making any external calls.



## [Info-1] The protocol uses ERC-7201 but does not include the `@custom:storage-location` annotation as recommended

The storage slot is defined using the `AXELAR_AMPLIFIER_GATEWAY_SLOT` constant. However, it does not use the `@custom:storage-location` annotation as recommended by ERC-7201. This annotation is important for documenting the storage location and preventing conflicts. While the current slot definition might function correctly, it does not adhere to best practices outlined in ERC-7201, which could lead to maintenance or upgrade challenges in the future.



```solidity

    /// @dev This slot contains the storage for this contract in an upgrade-compatible manner
    /// keccak256('AxelarAmplifierGateway.Slot') - 1;
    bytes32 internal constant AXELAR_AMPLIFIER_GATEWAY_SLOT =0xca458dc12368669a3b8c292bc21c1b887ab1aa386fa3fcc1ed972afd74a330ca;

    struct AxelarAmplifierGatewayStorage {
        address operator;
    }
```

Implement the `@custom:storage-location` annotation to document the storage location properly. This will help maintain clarity and avoid potential conflicts, aligning with best practices and ensuring easier upgrades or maintenance.

## [Info-2] Relying on bytecode length alone may not be reliable in all scenarios

The protocol currently checks in alot of places if the deployment was successful by verifying `tokenAddress.code.length == 0`. If the bytecode length is zero, it assumes the deployment failed:

```solidity
if (tokenAddress.code.length == 0) revert TokenDeploymentFailed();
```

However, relying on bytecode length alone may not be reliable in all scenarios. A zero length may not always indicate a failure, as the code at the address might be non-zero but not properly initialized.

Instead of checking the bytecode length, directly verify the presence of the code at the deployed address. This approach will provide a more accurate indication of whether the deployment succeeded. For example, check if the code at the address is not equal to an empty bytecode or validate the contract's existence in another reliable manner.
