## 1.1 Misleading Error Usage in `update_token_balance` for Overflow Scenarios

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/state.rs`

### Description:

In the `update_token_balance` function, the `Error::MissingConfig` error is used when handling overflow errors from the `checked_add` method. This is misleading because the `Error::MissingConfig` message indicates that the contract's configuration is missing, whereas the actual issue is an arithmetic overflow.

### Recommendation:

- Replace `Error::MissingConfig` with an appropriate error, such as `OverflowError`

  

## 1.2 Incorrect Error Handling for Insufficient Balance in `update_token_balance`

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/state.rs`

  

### Description:

In the `update_token_balance` function, the `Error::MissingConfig` error is used when handling insufficient balance errors from the `checked_sub` method. This is misleading because the error message suggests a missing configuration rather than an insufficient balance.

  

### Recommendation:

- Replace `Error::MissingConfig` with `Error::InsufficientBalance` to clearly indicate that the balance is insufficient for the transaction.

  

## 1.3 Lack of Proper Validation for `destination_address` in `call_contract`

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/client.rs`

  

### Description:

In the `call_contract` function, the `destination_address` is not properly validated. While it is initialized in the `execute_message` function using a registry of trusted addresses, validation should be ensured when this registry is modified. However, since the registry can only be updated by an admin, the potential impact of this issue is minimal.

### Recommendation:

- Implement validation checks for `destination_address` when the registry of trusted addresses is mutated, even though these operations are limited to admin access.

  

## 1.4 Potential Lack of Validation for `source_address` in `execute`

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/executable.rs`

  

### Description:

In the `execute` function of `AxelarExecutableClient`, the `source_address` is used directly from the message (`msg.source_address`) without apparent validation. The message originates from `state::update_msg_status` and seems to be stored during the `call_contract` execution. Without explicit validation, there is a risk of using an untrusted or invalid `source_address`.

### Recommendation:

- Ensure that the `source_address` is validated when the message is stored or before it is used in the `execute` function.

  

## 1.5 Insufficient Address Validation in `call_contract` Before Message Storage

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs`

  

### Description:

In the `call_contract` function, a new cross-chain message is created and saved using `state::save_incoming_msg`. However, there is no validation of the `source_address` or `destination_address` before the message is stored. While the `destination_address` is later validated during routing, this validation should ideally occur before saving the message to ensure only valid addresses are processed and stored.

  

### Recommendation:

- Perform validation of both `source_address` and `destination_address` prior to saving the message in the `call_contract` function.

- Ensure that invalid addresses are caught early to prevent invalid data from being stored or processed.

  

## 1.6 Vulnerable and Outdated Dependencies

  

**Severity:** Informational

**File:** Project Dependencies (via `cargo audit`)

  

### Description:

```shell

Crate: zerovec

Version: 0.10.2

Warning: yanked

  

Crate: zerovec-derive

Version: 0.10.2

Warning: yanked

  

error: 7 vulnerabilities found!

warning: 6 allowed warnings found

```

  

## 1.7 Missing Balance Information in `InsufficientBalance` Error Message

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/state.rs`

  

### Description:

  

The `InsufficientBalance` error includes the `balance` field, but this information is not included in the error message. As a result, important details about the available balance are omitted, which could be useful for debugging and logging purposes.

  

### Recommendation:

  

- Update the error message for `InsufficientBalance` to include the `balance` field. This will provide more context when the error is encountered.

  

## 1.8 Unused Error Messages in `Error` Enum

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/contract.rs`

  

### Description:

  

The `Error` enum defines several error messages that are not currently used anywhere in the code. These include `Execute`, `Unauthorized`, and `UntrustedSender`. Unused errors may indicate incomplete code paths or potential improvements that have not been fully implemented.

  

### Recommendation:

  

- Review the code to determine where these errors might be relevant, and integrate them if appropriate.

- Alternatively, remove the unused error variants if they are not necessary, to keep the codebase clean and maintainable.

  

## 1.9 Unused Error Variants in `Error` Enum

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs`

  

### Description:

  

The `Error` enum contains some error variants that are currently unused in the code. These include `SerializeWasmMsg` and `MessageNotApproved(CrossChainId)`. Having unused error variants can clutter the code and may indicate that certain error-handling paths are incomplete or unnecessary.

  

### Recommendation:

  

- Review the codebase to determine if these errors should be used in specific scenarios. If they are relevant, integrate them into the appropriate logic.

- If they are not needed, consider removing them to maintain a clean and manageable codebase.

  

## 1.10 Unused Error Variants in `Error` Enum

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/state.rs`

  

### Description:

  

The `Error` enum in `axelarnet-gateway/src/state.rs` contains several unused error variants. Specifically, the following variants are defined but not utilized anywhere in the codebase:

  

- `Std(#[from] StdError)`

- `MessageNotFound(CrossChainId)`

  

Unused error variants contribute to unnecessary code bloat and can be removed to simplify the code.

  

### Recommendation:

  

- Remove the unused error variants.

  

## 1.11 Incomplete Migration Implementation in `migrate` Function

  

**Severity:** Informational

**File:** `axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs`

  

### Description:

  

The `migrate` function in `contract.rs` is currently incomplete, as it only sets the contract version using `cw2::set_contract_version` without performing any actual migration logic.

  
  

## 1.12 Missing Migration Logic in `migrate` Function

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/contract.rs`

  

### Description:

The `migrate` function in `contract.rs` currently lacks implementation and simply returns a default response without executing any migration logic.

  

## 1.13 Redundant Fields in Message API

  

**Severity:** Informational

**File:** `axelar-amplifier/interchain-token-service/src/contract/execute.rs`

  

### Description:

  

The message API in the `apply_balance_tracking` function has redundant fields for the `ItsMessage::DeployInterchainToken` and `ItsMessage::DeployTokenManager` variants. These variants define multiple fields, but only the `token_id` field is utilized in the function.

  

### Recommendation:

  

- Remove unnecessary fields from the `ItsMessage::DeployInterchainToken` and `ItsMessage::DeployTokenManager` variants, keeping only `token_id` to simplify the message structure and reduce complexity in the API.

  

## 1.14 Potential Flow Limit Bypass in `_addFlow` Function

  

**Severity:** Low

**File:** `interchain-token-service/contracts/utils/FlowLimit.sol`

  

### Description:

  

The `_addFlow` function is vulnerable to a potential bypass where an attacker could multiplex the in and out flows, effectively stealing from both sides and circumventing the flow limit. While this vulnerability exists, its real-world implementation may be difficult, and the flow limiters still serve their purpose by mitigating simpler exploitation scenarios.

  
  

## 1.15 Incompatibility with Non-Ethereum Chains in `setup` Function

  

**Severity:** Low

**File:** `interchain-token-service/contracts/token-manager/TokenManager.sol`

  

### Description:

  

The `setup` function decodes `params_` as an Ethereum address (20 bytes) using the `toAddress()` method. However, the comment suggests this implementation is intended to support multiple chains by reserving 32 bytes for the address. The current implementation only works with Ethereum addresses due to the `toAddress()` function rejecting values longer than 20 bytes, which would make it incompatible with non-Ethereum chains.

  
  

## 1.16 Undistinguished Empty Case in `deployInterchainToken` Function

  

**Severity:** Low

**File:** `interchain-token-service/contracts/InterchainTokenService.sol`

  

### Description:

  

The `deployInterchainToken` function doesn't clearly distinguish between different cases, particularly when `destinationChain` is an empty string. The current implementation handles the empty `destinationChain` scenario by deploying a native interchain token. However, there is no explicit check or handling for an empty `minter` or other potentially critical parameters, which could lead to unintended behavior.

  
  

## 1.17 Lack of Rejection for Empty Data in `_expressExecute` Function

  

**Severity:** Low

**File:** `interchain-token-service/contracts/InterchainTokenService.sol`

  

### Description:

  

The `_expressExecute` function does not explicitly reject empty `data` payloads, which might be problematic in scenarios where the data is critical for execution logic. Although the function handles cases where `data.length == 0` by using a default value (`bytes32(0)`), this could lead to unexpected behavior or incomplete execution in certain interchain token transfers where data is required.

  

## 1.18 Redundant `setPauseStatus` Implementation

  

**Severity:** Informational

**File:** `interchain-token-service/contracts/InterchainTokenService.sol`

  

### Description:

  

The `setPauseStatus` function is a duplicate of `_setPaused` from the `Pausable` contract. The function calls `_pause()` and `_unpause()`, which internally invoke `_setPaused(true)` and `_setPaused(false)`, respectively. This redundancy may lead to unnecessary complexity and maintenance overhead.




### 1.19 Severity: Low
interchain-token-service/contracts/TokenHandler.sol:225-230
```
    function _approveGateway(address tokenAddress, uint256 amount) internal {
        uint256 allowance = IERC20(tokenAddress).allowance(address(this), gateway);
        if (allowance == 0) {
            IERC20(tokenAddress).safeCall(abi.encodeWithSelector(IERC20.approve.selector, gateway, amount));
        }
    }
```

In order to renew the approval, `allowance` should be compared against `amount`, not `0`. The caller might expect that after the call, `allowance == amount`. But it can be lower, or almost zero.

In practice, the `amount` is max value for `uint256`. This triggers "infinite approval" mode that doesn't reduce allowance after transfers.

### 1.20 Severity: Low
interchain-token-service/contracts/utils/TokenManagerDeployer.sol:30-33
```
        // slither-disable-next-line too-many-digits
        bytes memory bytecode = abi.encodePacked(type(TokenManagerProxy).creationCode, args);

        tokenManager = _create3(bytecode, tokenId);
```
Here could be different scenarios depending on the type of token manager. In case of `lock/unlock`, I guess, the ownership will be verified so front-running is not possible. What about `burn/mint` type? The impact looks like phishing in this case though, not like unavoidable stealing. The original deployer might need to be cautious and check privileges after the deployment to ensure its ownership.