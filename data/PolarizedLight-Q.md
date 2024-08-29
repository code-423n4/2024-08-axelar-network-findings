# Team PolarizedLight Axelar QA Report

# Low Findings

## [Low-1] Gas Griefing Vulnerability in Low-Level Calls

**Overview:**

The InterchainTokenService contract uses low-level `delegatecall` operations in multiple functions, which could potentially expose the contract to gas griefing attacks.

**Description:**

The contract uses `delegatecall` to interact with various components like tokenHandler, tokenManagerDeployer, and interchainTokenDeployer. While `delegatecall` is a powerful feature in Solidity, it can be exploited if not used carefully. The main risk here is that the called contracts could return an excessive amount of data, causing the calling contract (InterchainTokenService) to use an unexpected amount of gas for memory allocation.

For example, in the `_takeToken` function:

```solidity
function _takeToken(bytes32 tokenId, address from, uint256 amount, bool tokenOnly) internal returns (uint256, string memory symbol) {
    (bool success, bytes memory data) = tokenHandler.delegatecall(
        abi.encodeWithSelector(ITokenHandler.takeToken.selector, tokenId, tokenOnly, from, amount)
    );
    if (!success) revert TakeTokenFailed(data);
    (amount, symbol) = abi.decode(data, (uint256, string));
    return (amount, symbol);
}
```

If the `tokenHandler` contract is compromised or malicious, it could return an extremely large amount of data, causing this function to consume much more gas than expected.

**CodeLocation:**

This vulnerability is present in multiple functions throughout the contract, including:

- `_takeToken` (line 1189)
- `_giveToken` (line 1202)
- `_deployTokenManager` (line 1054)
- `_deployInterchainToken` (line 1091)

**Impact:**

While the use of `delegatecall` to internal contracts doesn't present the same level of risk as calls to external contracts, it still introduces the potential for unexpected gas consumption if the called functions return large amounts of data.

**Recommended mitigations:**

1. Ensure all internal contracts have well-defined and tested limits on returned data size.
2. Implement comprehensive gas usage tests for all paths involving `delegatecall`.
3. Consider adding gas limits to `delegatecall` operations as an additional safeguard.

The use of `delegatecall` for internal operations in the `InterchainTokenService.sol` contract requires careful management to ensure consistent and predictable gas consumption. Implementing the suggested mitigations would further enhance the robustness and efficiency of the contract's operations.


## [Low-2] Unreliable Contract Detection Method in `Create3Fixed.sol`

**Overview:**

The Create3Fixed contract employs the deprecated and unreliable `isContract()` method to determine if an address is a contract, potentially introducing security vulnerabilities and leading to incorrect contract behavior.

**Description:**

The `isContract()` method is no longer considered a reliable means of distinguishing between Externally Owned Accounts (EOAs) and contracts. This method can produce false positives or negatives, particularly when dealing with proxy contracts or contracts created during transaction execution. The Create3Fixed contract continues to rely on this method for critical decision-making in its deployment process.

**Code Location:**

The problematic code is located in the `_create3` function of the `Create3Fixed` contract:

```solidity
function _create3(bytes memory bytecode, bytes32 deploySalt) internal returns (address deployed) {
    deployed = _create3Address(deploySalt);
    if (bytecode.length == 0) revert EmptyBytecode();
    if (deployed.isContract()) revert AlreadyDeployed();
    // ... rest of the function
}
```

**Impact:**

This vulnerability could lead to incorrect identification of gateway tokens, potentially allowing non-gateway tokens to be treated as gateway tokens or vice versa. This could impact the correct functioning of the `registerCanonicalInterchainToken` function, which relies on this check to prevent gateway tokens from being registered as canonical tokens.

**Recommended mitigations:**

1. Implement a more robust token validation mechanism that doesn't rely solely on address comparison. This could involve:

   - Maintaining a whitelist of approved gateway tokens.
   - Implementing an interface check to verify if the token implements expected gateway token functions.
   - Using a registry contract that keeps track of all valid gateway tokens, including their proxy and implementation addresses.

2. Consider using a unique identifier for each token instead of relying on the symbol, which could be duplicated across different tokens.

3. If possible, consult with the gateway contract to verify if a token is indeed a gateway token, rather than relying on local checks.
  
Example of a potential improvement:

```solidity
interface IGatewayTokenRegistry {
    function isGatewayToken(address token) external view returns (bool);
}

contract InterchainTokenFactory {
    IGatewayTokenRegistry public gatewayTokenRegistry;
    
    // ... other contract code ...

    function _isGatewayToken(address token) internal view returns (bool) {
        return gatewayTokenRegistry.isGatewayToken(token);
    }
}
```

The current implementation of `isGatewayToken` function poses a risk to the correct identification and handling of gateway tokens within the `InterchainTokenFactory.sol` contract. By implementing a more robust validation mechanism, such as using a dedicated registry or interface checks, the contract can ensure accurate identification of gateway tokens, thereby assisting in preventing potential exploits or misuse of the contract's functionalities.

## [Low-3] Use of Type-Unsafe `abi.encodeWithSelector` in Multiple Contracts 

**Overview:**

The smart contract extensively uses `abi.encodeWithSelector` for function calls, which is not type-safe and can lead to potential errors and vulnerabilities.

**Description:**

`abi.encodeWithSelector` is used throughout the contract for encoding function calls. This method does not provide compile-time type checking, potentially allowing mismatched argument types to pass undetected. This can lead to unexpected behavior, failed transactions, or in worst cases, security vulnerabilities. For Solidity versions 0.8.13 and above, `abi.encodeCall` is available as a type-safe alternative. It performs full type checking at compile-time, ensuring that the arguments match the function signature and reducing the risk of errors due to incorrect types or typographical mistakes.

**Code Locations:**

1. `InterchainTokenService.sol`#L412-L413

   Line 413: `abi.encodeWithSelector(ITokenHandler.transferTokenFrom.selector, tokenId, msg.sender, destinationAddress, amount)`

2. `InterchainTokenService.sol`#L826-L827

   Line 827: `abi.encodeWithSelector(IGatewayCaller.callContract.selector, destinationChain, destinationAddress, payload, metadataVersion, gasValue)`

3. `InterchainTokenService.sol`#L858-L859

   Line 859: `abi.encodeWithSelector(IGatewayCaller.callContractWithToken.selector, destinationChain, destinationAddress, payload, symbol, amount, metadataVersion, gasValue)

4. `InterchainTokenService.sol`#L1055-L1056

   Line 1056: `abi.encodeWithSelector(ITokenManagerDeployer.deployTokenManager.selector, tokenId, tokenManagerType, params)

5. `InterchainTokenService.sol`#L1065-L1066

   Line 1066: `abi.encodeWithSelector(ITokenHandler.postTokenManagerDeploy.selector, tokenManagerType, tokenManager_)

6. `InterchainTokenService.sol`#L1103-L1104

   Line 1104: `abi.encodeWithSelector(IInterchainTokenDeployer.deployInterchainToken.selector, salt, tokenId, minter, name, symbol, decimals)`

7. `InterchainTokenService.sol`#L1190-L1191

   Line 1191: `abi.encodeWithSelector(ITokenHandler.takeToken.selector, tokenId, tokenOnly, from, amount)

8. `InterchainTokenService.sol`#L1203-L1204

   Line 1204: `abi.encodeWithSelector(ITokenHandler.giveToken.selector, tokenId, to, amount)

9. `TokenHandler.so`l#L206-L206

   Line 206: abi.encodeWithSelector(IERC20MintableBurnable.mint.selector, to, amount)

10. `TokenHandler.sol`#L210-L210

    Line 210: `abi.encodeWithSelector(IERC20MintableBurnable.burn.selector, from, amount)

11. `TokenHandler.sol`#L222-L222

    Line 222: `abi.encodeWithSelector(IERC20BurnableFrom.burnFrom.selector, from, amount)

12. `TokenHandler.sol`#L228-L228

    Line 228: `abi.encodeWithSelector(IERC20.approve.selector, gateway, amount)

13. `TokenManagerProxy.sol`#L42-L42

    Line 42: `abi.encodeWithSelector(IProxy.setup.selector, params)

14. `TokenManager.sol`#L181-181

    Line 181: `abi.encodeWithSelector(IERC20.approve.selector, interchainTokenService, UINT256_MAX)

15. `TokenManager.sol`#L203-L203

    Line 203: `abi.encodeWithSelector(IERC20MintableBurnable.mint.selector, to, amount)

16. `TokenManager.sol`#L214-L214

    Line 214: `abi.encodeWithSelector(IERC20MintableBurnable.burn.selector, from, amount)

**Impact:**

The use of `abi.encodeWithSelector` introduces the following risks:

1. Silent failures: Incorrectly typed arguments may not cause immediate errors but could lead to unexpected behavior.
2. Reduced code reliability: The lack of compile-time type checking increases the likelihood of bugs.
3. In certain scenarios, type mismatches could be exploited by attackers.

**Recommended Mitigations:**

1. For Solidity versions 0.8.13 and above, replace all instances of `abi.encodeWithSelector` with `abi.encodeCall`.
2. If using an earlier Solidity version, consider upgrading to take advantage of `abi.encodeCall`.

The widespread use of `abi.encodeWithSelector` in this contract presents a  risk to its reliability and security. By transitioning to `abi.encodeCall` or implementing strict type checking measures, the contract's robustness can be substantially improved, reducing the potential for errors and vulnerabilities stemming from type mismatches.

## [Low-4] Lack of Storage Gap in Upgradeable Contracts

**Overview:**

Multiple upgradeable contracts in the codebase lack a storage gap, which could lead to storage collision issues during future upgrades.

**Description:**

The contracts `AxelarAmplifierGateway.sol`, `InterchainTokenService.sol`, and `InterchainTokenFactory.sol` are all upgradeable (inheriting from Upgradable) but do not implement a storage gap. In upgradeable contracts, it's crucial to include a storage gap to allow for future additions of state variables without causing storage collisions.

A storage gap is typically implemented as an array of unused slots at the end of a contract's storage layout. This gap provides flexibility for future upgrades by reserving space that can be used for new state variables without shifting the storage of child contracts.

The absence of a storage gap can lead to issues if new variables are added in future upgrades, potentially overwriting or corrupting the storage of child contracts.

**Code Location:**

1. AxelarAmplifierGateway.sol

```solidity
contract AxelarAmplifierGateway is BaseAmplifierGateway, BaseWeightedMultisig, Upgradable, IAxelarAmplifierGateway {
    // ... (no storage gap)
}
```

2. InterchainTokenService.sol

```solidity
contract InterchainTokenService is
    Upgradable,
    Operator,
    Pausable,
    Multicall,
    Create3AddressFixed,
    ExpressExecutorTracker,
    InterchainAddressTracker,
    IInterchainTokenService {
    // ... (no storage gap)
}
```

3. InterchainTokenFactory.sol

```solidity
contract InterchainTokenFactory is IInterchainTokenFactory, ITokenManagerType, Multicall, Upgradable {
    // ... (no storage gap)
}
```

The absence of a storage gap can lead to issues if new variables are added in future upgrades, potentially overwriting or corrupting the storage of child contracts.

**Recommended Mitigation:**

Add a storage gap to each upgradeable contract. This can be done by including a private array of unused uint256 values at the end of each contract:

```Diff
contract AxelarAmplifierGateway is BaseAmplifierGateway, BaseWeightedMultisig, Upgradable, IAxelarAmplifierGateway {
    // ... existing code ...
    // Add this at the end of the contract
+    uint256[50] private __gap;
}
```

Repeat this process for `InterchainTokenService.sol` and `InterchainTokenFactory.sol`. The size of the gap (in this example, `50`) can be adjusted based on the anticipated future needs of the contract.

Implementing storage gaps in upgradeable contracts is a security measure that ensures the longevity and stability of the protocol. By adding these gaps, we significantly reduce the risk of storage collisions during future upgrades.

I understand you want me to format the findings from the attached document. I'll format the two main findings in the style consistent with the earlier report:


# Non-Critical Findings

## [NonCritical-1] Unused Named Return Variables

**Overview:** 

Multiple functions in the contract use named return variables that are not directly used within the function body. While this doesn't affect the functionality of the code, it can lead to confusion and is considered a code quality issue.

**Description:** 

Named return variables are declared in the function signature but not used within the function body. Instead, the functions use a return statement with an expression. This practice doesn't take advantage of the named return feature and can be misleading to readers of the code.

**Code Location:**

1. AxelarAmplifierGateway.sol:

```solidity
function validateProof(bytes32 dataHash, Proof calldata proof) external view returns (bool isLatestSigners) {
    return _validateProof(dataHash, proof);
}
```

2. InterchainTokenService.sol:

```solidity
function _getInterchainTokenSalt(bytes32 tokenId) internal pure returns (bytes32 salt) {
    return keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_SALT, tokenId));
}
```

3. InterchainTokenDeployer.sol:

```solidity
function deployedAddress(bytes32 salt) external view returns (address tokenAddress) {
    return _create3Address(salt);
}
```

**Impact:** 

This issue does not affect the functionality or security of the contract. However, it impacts code readability and could potentially lead to confusion during code maintenance or auditing.

**Recommended mitigations:**

1. Remove the named return variables and use unnamed returns:

```solidity
function validateProof(bytes32 dataHash, Proof calldata proof) external view returns (bool) {
    return _validateProof(dataHash, proof);
}
```

2. Or Axelar can, use the named return variables within the function body:

```solidity
function _getInterchainTokenSalt(bytes32 tokenId) internal pure returns (bytes32 salt) {
    salt = keccak256(abi.encode(PREFIX_INTERCHAIN_TOKEN_SALT, tokenId));
}
```

While the use of unused named return variables does not pose a security risk, addressing this issue will improve code quality and readability. Consistent use of return variable naming conventions across the codebase will make it easier for developers and auditors to understand and maintain the code in the future.

## [NonCritical-2] Redundant inheritance of ERC20

**Overview:** 

The InterchainToken contract inherits from both ERC20 and ERC20Permit, which is redundant since ERC20Permit already extends ERC20.

**Description:** 

The `InterchainToken.sol` contract is currently inheriting from multiple base contracts, including both ERC20 and ERC20Permit. While this doesn't cause immediate functional issues, it's an unnecessary inheritance that could lead to confusion and potential problems in the future. ERC20Permit is an extension of ERC20, meaning it already includes all ERC20 functionality. By inheriting from both, the contract is duplicating the ERC20 inheritance, which goes against best practices for clear and efficient contract design.

**Code Location:** File: paste.txt Line 21:

```solidity
contract InterchainToken is InterchainTokenStandard, ERC20, ERC20Permit, Minter, IInterchainToken {
```

**Impact:**

This redundancy doesn't introduce direct security vulnerabilities but may lead to:

1. Code bloat and unnecessary complexity
2. Potential confusion for developers maintaining or auditing the code
3. Slightly increased gas costs due to longer bytecode

**Recommended Mitigation:** 

Remove the redundant ERC20 inheritance from the contract definition. The modified line should look like this:

```solidity
contract InterchainToken is InterchainTokenStandard, ERC20Permit, Minter, IInterchainToken {
```


While this finding doesn't present an immediate security risk, addressing it will improve the contract's design and maintainability. Implementing this change will contribute to the overall quality and professionalism of the InterchainToken contract.

## [NonCritical-3] Misuse of `pure` Functions with Storage Pointers in Multiple Contracts

**Overview:** 

Multiple contracts in the codebase contain functions incorrectly marked as `pure` that return storage pointers. This contradicts the expected behavior of `pure` functions and may lead to unexpected state interactions.

**Description:** 

In Solidity, `pure` functions are intended to neither read from nor modify the contract's state. But multiple functions in the reviewed contracts are marked as `pure` while returning storage pointers, which inherently interact with the contract's state. This misuse can lead to subtle bugs and unexpected behavior, as the compiler does not flag this contradiction.

**Code Locations:**

1. `BaseAmplifierGateway.sol`:

```solidity
function _baseAmplifierGatewayStorage() private pure returns (BaseAmplifierGatewayStorage storage slot) {
    assembly {
        slot.slot := BASE_AMPLIFIER_GATEWAY_SLOT
    }
}
```

2. `AxelarAmplifierGateway.sol`:

```solidity
function _axelarAmplifierGatewayStorage() private pure returns (AxelarAmplifierGatewayStorage storage slot) {
    assembly {
        slot.slot := AXELAR_AMPLIFIER_GATEWAY_SLOT
    }
}
```

3. `BaseWeightedMultisig.sol`:

```solidity
function _baseWeightedMultisigStorage() internal pure returns (BaseWeightedMultisigStorage storage slot) {
    assembly {
        slot.slot := BASE_WEIGHTED_MULTISIG_SLOT
    }
}
```


**Impact:** 

The incorrect use of `pure` for functions returning storage pointers has the following implications:

1. Misleading function semantics: Developers and auditors may assume these functions do not interact with state, leading to misunderstandings about the contract's behavior.

2. Potential for unintended state reads or modifications: If these functions are used in contexts where state interaction is not expected, it could lead to bugs or security vulnerabilities.

3. Reduced gas optimization: The compiler may not apply certain optimizations it would for truly `pure` functions.

**Recommended Mitigations:**

1. Change the `pure` modifier to `view` for all functions that return storage pointers. This correctly indicates that the function reads from, but does not modify, the contract's state.

2. Review all uses of these functions to ensure they are not being relied upon in contexts where state interaction is undesirable.

3. If state access is not actually required, refactor the functions to avoid using storage pointers and maintain the `pure` designation.

The misuse of `pure` functions with storage pointers in these contracts represents an oversight that could lead to unexpected behavior and potential vulnerabilities. By correctly designating these functions as `view` or refactoring them to truly be `pure`, the contract's behavior becomes more transparent and predictable. 

## [NonCritical-4] Redundant Signature Recovery ID (v) Check in ERC20Permit Contract

**Overview:** The ERC20Permit contract implements an unnecessary check for the signature recovery ID (v) before calling the `ecrecover` function. This check is redundant as `ecrecover` inherently validates these values.

**Description:** 

In the `permit` function of the `ERC20Permit.sol` contract, there is an explicit check to ensure that the signature recovery ID (v) is either 27 or 28:

```solidity
if (v != 27 && v != 28) revert InvalidV();
```

This check is performed before calling the `ecrecover` function:

```solidity
address recoveredAddress = ecrecover(digest, v, r, s);
```

However, this check is unnecessary because the `ecrecover` function inherently handles invalid v values. If an invalid v value is provided, `ecrecover` will return the zero address, which will then fail the subsequent check:

```solidity
if (recoveredAddress != issuer) revert InvalidSignature();
```

While this redundant check does not introduce any security vulnerabilities, it does consume unnecessary gas and adds complexity to the code.

**Code Location:**

File: ERC20Permit.sol
Lines: 76 (check) and 86 (ecrecover call)

**Impact:** 

This issue does not pose a security risk but leads to slightly higher gas costs for users when calling the `permit` function.

**Recommended Mitigations:** Remove the redundant check for v values:

```diff
// Remove this line
- if (v != 27 && v != 28) revert InvalidV();
```

The `ecrecover` function and the subsequent check for a valid recovered address are sufficient to ensure the signature's validity.

Addressing it will optimize gas usage and simplify the contract code. This change aligns with best practices in Ethereum smart contract development, emphasizing efficiency and clarity in code implementation.

## [Non-Critical-5] Potential for Stale Reads in TokenHandler Contract Functions

**Overview:**

The TokenHandler contract contains functions that retrieve token manager information before executing their main logic. While this structure doesn't present immediate security risks, it could potentially lead to the use of slightly outdated information under specific circumstances.

**Description:**

The `transferTokenFrom`, `takeToken`, and `giveToken` functions in the TokenHandler contract fetch token manager details via external calls prior to performing their core operations. This sequence creates a small window where the retrieved information could become stale if the contract state changes between the initial read and the execution of the main logic.

**Code Location:**

TokenHandler.sol:

- transferTokenFrom: Lines 136-137
- takeToken: Lines 97-98
- giveToken: Lines 46-48

**Impact:**

The severity of this issue is considered Low due to the following factors:

1. Limited Exploitability: While read-only reentrancy is theoretically possible, practical exploitation is challenging and requires specific conditions to be met.

2. No Direct State Changes: The vulnerability doesn't allow direct modification of contract state, limiting its potential for immediate financial damage.

3. Subtle Implications: The main risk lies in the potential for inconsistent reads of contract state, which could lead to:

   a. Incorrect decision-making in subsequent operations based on outdated information.
   b. Potential manipulation of token transfer amounts or recipient addresses if an attacker can influence the contract's logic between reads.
  
4. Complexity of Exploitation: Successfully exploiting this vulnerability would require intricate knowledge of the contract's inner workings and precise timing of transactions.

5. Indirect Effects: In a worst-case scenario, this could lead to:
   a. Slight discrepancies in token balances or transfer amounts.
   b. Inconsistent execution of token operations across multiple transactions.
   c. Potential for minor economic gains for sophisticated attackers, though the profit potential is likely limited.

**Recommended Mitigations:**

1. Implement the checks-effects-interactions pattern by moving the external calls to the end of the functions.
2. Use a reentrancy guard modifier on the affected functions to prevent nested calls.
3. Consider caching the token manager information to avoid repeated external calls within the same transaction.

Example fixes for the affected functions:

1. `giveToken` function:

```diff
function giveToken(bytes32 tokenId, address to, uint256 amount) external payable returns (uint256, address) {
    address tokenManager = _create3Address(tokenId);
+   uint256 tokenManagerType;
+   address tokenAddress;

-   (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

    ITokenManager(tokenManager).addFlowIn(amount);

+   // Cache the token manager information
+   (tokenManagerType, tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

    if (tokenManagerType == uint256(TokenManagerType.NATIVE_INTERCHAIN_TOKEN)) {
        _giveInterchainToken(tokenAddress, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.MINT_BURN) || tokenManagerType == uint256(TokenManagerType.MINT_BURN_FROM)) {
        _mintToken(tokenManager, tokenAddress, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
        _transferTokenFrom(tokenAddress, tokenManager, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK_FEE)) {
        amount = _transferTokenFromWithFee(tokenAddress, tokenManager, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.GATEWAY)) {
        _transferToken(tokenAddress, to, amount);
    } else {
        revert UnsupportedTokenManagerType(tokenManagerType);
    }
    return (amount, tokenAddress);
}
```

2. `takeToken` function:

```diff
function takeToken(bytes32 tokenId, bool tokenOnly, address from, uint256 amount) external payable returns (uint256, string memory) {
    address tokenManager = _create3Address(tokenId);
+   uint256 tokenManagerType;
+   address tokenAddress;

-   (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

    ITokenManager(tokenManager).addFlowOut(amount);
+   // Cache the token manager information
+   (tokenManagerType, tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

    if (tokenManagerType == uint256(TokenManagerType.NATIVE_INTERCHAIN_TOKEN)) {
        return _takeInterchainToken(tokenAddress, tokenOnly, from, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.MINT_BURN) || tokenManagerType == uint256(TokenManagerType.MINT_BURN_FROM)) {
        return _burnToken(tokenManager, tokenAddress, tokenOnly, from, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
        return _takeTokenWithAmount(tokenAddress, tokenOnly, from, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK_FEE)) {
        return _takeTokenWithAmountAndFee(tokenAddress, tokenOnly, from, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.GATEWAY)) {
        return _takeTokenWithAmount(tokenAddress, tokenOnly, from, amount);
    } else {
        revert UnsupportedTokenManagerType(tokenManagerType);
    }
}
```

3. `transferTokenFrom` function:

```diff
function transferTokenFrom(bytes32 tokenId, address from, address to, uint256 amount) external payable returns (uint256) {
    address tokenManager = _create3Address(tokenId);
    
+   uint256 tokenManagerType;
+   address tokenAddress;

-   (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

+   // Cache the token manager information
+   (tokenManagerType, tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

    if (tokenManagerType == uint256(TokenManagerType.NATIVE_INTERCHAIN_TOKEN)) {
        _transferTokenFrom(tokenAddress, from, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.MINT_BURN) || tokenManagerType == uint256(TokenManagerType.MINT_BURN_FROM)) {
        _burnToken(tokenManager, tokenAddress, false, from, amount);
        _mintToken(tokenManager, tokenAddress, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
        _transferTokenFrom(tokenAddress, from, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK_FEE)) {
        amount = _transferTokenFromWithFee(tokenAddress, from, to, amount);
    } else if (tokenManagerType == uint256(TokenManagerType.GATEWAY)) {
        _transferTokenFrom(tokenAddress, from, to, amount);
    } else {
        revert UnsupportedTokenManagerType(tokenManagerType);
    }
    return amount;
}
```

Although this doesn't pose a significant security threat, it represents a minor deviation from optimal contract design practices. The likelihood of using outdated information is low and would require very specific timing and conditions to occur.
