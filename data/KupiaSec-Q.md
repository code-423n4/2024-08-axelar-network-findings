## L-01 Mismatch between codebase and comments

[Here](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L316C96-L317C87), the comment says:
" If the `minter` parameter is empty bytes then a mint/burn TokenManager is used, otherwise a lock/unlock TokenManager is used."
But, the [code](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L345) always uses the `NATIVE_INTERCHAIN_TOKEN` TokenManager.

```solidity
        if (bytes(destinationChain).length == 0) {
            address tokenAddress = _deployInterchainToken(tokenId, minter, name, symbol, decimals);

L345:       _deployTokenManager(tokenId, TokenManagerType.NATIVE_INTERCHAIN_TOKEN, abi.encode(minter, tokenAddress));
        } else {
            _deployRemoteInterchainToken(tokenId, name, symbol, decimals, minter, destinationChain, gasValue);
        }
```

## L-02 Mismatch between codebase and comments

[Here](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L124), the comment says:
"The address to receive the initially minted tokens."
But, the [code](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L151) mints the initial tokens to `msg.sender`

```solidity
        token.mint(sender, initialSupply);
```

## L-03 In `InterchainTokenFactory.deployRemoteInterchainToken` function, it gets the token information without checking existance of tokenManager

In `InterchainTokenFactory.deployRemoteInterchainToken` function, it gets the token information using `interchainTokenService.interchainTokenAddress(tokenId)` instead of `interchainTokenService.validTokenAddress(tokenId)`.

https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L196

```diff
-        IInterchainToken token = IInterchainToken(interchainTokenService.interchainTokenAddress(tokenId));
+        IInterchainToken token = IInterchainToken(interchainTokenService.validTokenAddress(tokenId));
```

## L-04 The `InterchainTokenService.expressExecute` function does not have `onlyRemoteService` modifier

The `onlyRemoteService` modifier is used to ensure that only a remote InterchainTokenService can invoke the execute function.
But `expressExecute` function does not check this modifier. It is recommended to add the modifier as following:

```diff
    function expressExecute( // @audit-info does not check MetadataVersion.EXPRESS_CALL
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
-   ) public payable whenNotPaused {
+   ) public payable whenNotPaused onlyRemoteService(sourceChain, sourceAddress){
        [...]
    }
```

## L-05 Not only owner of `InterchainTokenFactory` contract but also anyone can register 'canonical' gateway tokens

The [InterchainTokenFactory.registerGatewayToken](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L301) has `onlyOwner` modifier.

```solidity
L301:   function registerGatewayToken(bytes32 tokenIdentifier, string calldata symbol) external onlyOwner returns (bytes32 tokenId) {
            address tokenAddress = gateway.tokenAddresses(symbol);
            if (tokenAddress == address(0)) revert NotGatewayToken(symbol);

            bytes memory params = abi.encode('', tokenAddress);
            bytes32 salt = gatewayTokenSalt(tokenIdentifier);

L308:       tokenId = interchainTokenService.deployTokenManager(salt, '', TokenManagerType.GATEWAY, params, 0);
        }
```

But users can register the `canonical` gateway tokens by calling `InterchainTokenService.deployTokenManager` directly with parameters like L308.
In the `InterchainTokenService.deployTokenManager`, if `tokenManager` type is `GATEWAY`, add the checking that `msg.sender` is `InterchainTokenFactory` contract.