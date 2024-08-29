# [L-01] Missing virtual keyword in `TokenManager::interchainTokenId` and `TokenManager::implementationType` so every time these functions are called they will revert, if a derived contract wants to use them it should override these functions.

## Found in 
https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/token-manager/TokenManager.sol#L68-#L83

### `interchainTokenId` has different signatures: external view/ public pure/ public view:
https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/interfaces/IBaseTokenManager.sol#L13-L14

https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/interfaces/IInterchainToken.sol#L33

https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/interfaces/ITokenManagerProxy.sol#L24

https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/interchain-token/InterchainTokenStandard.sol#L18

### `implementationType` has different signatures: external view/ external pure
https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/interfaces/ITokenManager.sol#L30

# [L-02] Missing @dev must revert param for following implementations

## Description
Every implementation of `InterchainTokenExecutable::__executeWithInterchainToken` must revert if incorrect input is provided, otherwise it will return wrong results.
In some implementation of `InterchainTokenExecutable::__executeWithInterchainToken` doesn't revert the functionality of the protocol will be disrupted as `InterchainTokenExecutable::executeWithInterchainToken` only calls `_executeWithInterchainToken` and immediately returns `EXECUTE_SUCCESS`.

## Found in
https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/executable/InterchainTokenExecutable.sol#L38-#L61

https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/executable/InterchainTokenExecutable.sol#L63-#L83

## Recommended Mitigation Steps
Add the following information in the natspec:
```diff
 /**
     * @notice Internal function containing the logic to be executed with interchain token transfer.
     * @dev Logic must be implemented by derived contracts.
+     * @dev Every implemetation must revert if incorrect data is provided.
     * @param commandId The unique message id.
     * @param sourceChain The source chain of the token transfer.
     * @param sourceAddress The source address of the token transfer.
     * @param data The data associated with the token transfer.
     * @param tokenId The token ID.
     * @param token The token address.
     * @param amount The amount of tokens being transferred.
 */
    function _executeWithInterchainToken(
        bytes32 commandId,
        string calldata sourceChain,
        bytes calldata sourceAddress,
        bytes calldata data,
        bytes32 tokenId,
        address token,
        uint256 amount
    ) internal virtual;
```

# [L-03] Incorrect natspec in `WightedMultisigTypes.sol`

## Description

In `WightedMultisigTypes.sol` the `WeightedSigner` struct natspec have one additional @param treshold that does not occurr in the struct.

## Found in

https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/types/WeightedMultisigTypes.sol#L5-L14

## Recommended Mitigation Steps
Remove the `@param treshold`

```diff
/**
 * @notice This struct represents the weighted signers payload
 * @param signers The list of signers
 * @param weights The list of weights
- * @param threshold The threshold for the signers
 */
struct WeightedSigner {
    address signer;
    uint128 weight;
}
```

# [L-04] Method `InterchainTokenStandart::_beforeInterchainTransfer` is virtual, but its functionality is not implemented in the derived contract in `InterchainToken.sol` or anywere else except in test files.

Nothing will happen before the transfer so no one can approve the tokenManager if needed,
to allow users for a 1-call transfer in case of a lock-unlock token manager.