# [L-01] GasToken might be left in the contract
File:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/utils/GatewayCaller.sol#L35-L69
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/utils/GatewayCaller.sol#L81-L118
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L172-L210
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L266-L294
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L286-L311
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L327-L349
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L454-L478
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L488-L511

Those functions are `payable`, and can receive gas token(ETH/MATIC/BNB) and forward the gas token to other contract. The issue is that those function doesn't check if `gasValue == msg.value`, if `msg.value > gasValue`, the dust gas token will be left in the contract.
The issue already exists in the onchain contract. For example, [ITS](https://etherscan.io/address/0xB5FB4BE02232B1bBA4dC8f81dc24C26980dE9e3C) has `0.050951605452040975 ETH` left

# [L-02] different abi.decode parameters are used for same payload
File:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L656-L665
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L707-L712
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L1219-L1226
In `contractCallWithTokenValue`, the same `payload` are decoded in both `_checkPayloadAgainstGatewayData` and `_contractCallValue`, but those two functions use different parameter to decode the same payload, which might cause some confuse.
```solidity
 707     function _checkPayloadAgainstGatewayData(bytes memory payload, string calldata tokenSymbol, uint256 amount) internal view {
 708         (, bytes32 tokenId, , , uint256 amountInPayload) = abi.decode(payload, (uint256, bytes32, uint256, uint256, uint256)); <<<--- Here (uint256, bytes32, uint256, uint256, uint256) is used
 709 
 710         if (validTokenAddress(tokenId) != gateway.tokenAddresses(tokenSymbol) || amount != amountInPayload)
 711             revert InvalidGatewayTokenTransfer(tokenId, payload, tokenSymbol, amount);
 712     }
```
```solidity
1219     function _contractCallValue(bytes calldata payload) internal view returns (address, uint256) {
1220         (uint256 messageType, bytes32 tokenId, , , uint256 amount) = abi.decode(payload, (uint256, bytes32, bytes, bytes, uint256)); <<<--- Here (uint256, bytes32, bytes, bytes, uint256) is used
1221         if (messageType != MESSAGE_TYPE_INTERCHAIN_TRANSFER) {
1222             revert InvalidExpressMessageType(messageType);
1223         }
1224 
1225         return (validTokenAddress(tokenId), amount);
1226     }
```

# [L-03] `InterchainTokenService._expressExecute` and `InterchainTokenService._processInterchainTransferPayload` should check if the `destinationAddress` supports the API bofore calling
File:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L430-L439
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L763-L772
I'll take `InterchainTokenService._expressExecute` as an example, in [InterchainTokenService._expressExecute](https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L430-L439), if `data.length > 0`, the function calls `IInterchainTokenExpressExecutable(destinationAddress).expressExecuteWithInterchainToken` without checking if `destinationAddress` supports the API, and if destinationAddress doesn't support the API, the function will revert.
This is possible expecially when `destinationAddress` is a proxy, and the implementation has some change but forget to support the API