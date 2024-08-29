### [L-01] Wrong data decoding in `_checkPayloadAgainstGatewayData`

The `_checkPayloadAgainstGatewayData` decodes `payload` the following way:
```solidity
(, bytes32 tokenId, , , uint256 amountInPayload) = abi.decode(payload, (uint256, bytes32, uint256, uint256, uint256));
```

The issue is that this is incorrect as the correct approach would be:
```solidity
(, bytes32 tokenId, , , uint256 amountInPayload) = abi.decode(payload, (uint256, bytes32, bytes, bytes, uint256, bytes));
```

Currently, this is not an issue as the values decoded wrongly are not used, but may pose a problem in future upgrades.

### [L-02] `InterchainTokenIdClaimed` is not emitted in `deployInterchainToken`

The `InterchainTokenIdClaimed` event is emitted in `deployTokenManager`, however the emition is omitted in `deployInterchainToken`, which has the same functionality as `deployTokenManager`, except that it also deploys an interchain token. Thus, the `InterchainTokenIdClaimed` should be emitted in both functions.

### [L-03] `expressExecute` can be invoked by malicious express executors

Currently `expressExecute` can be invoked by any address, without providing actual data, connected to a valid interchain transfer. As a result, a malicious caller can set the amount variable to 0 or 1 wei, in order to invoke `expressExecuteWithInterchainToken` on any `destinationAddress` through ITS, without actually transferring any funds. This is not dangerous for the protocol, but may be harmful for the `destinationAddress` if their `expressExecuteWithInterchainToken` implementation is not sufficiently validated. Also the `InterchainTransferReceived` can be freely emitted with invalid data.

To avoid any risks, the protocol team must be aware that `InterchainTransferReceived` may return harmful data, and users of the protocol must be informed that `expressExecuteWithInterchainToken` must be thoroughly validated.

### [L-04] Funds may be stuck in ITS

`interchainTransfer` and `callContractWithInterchainToken` send `gasValue`, provided by the caller, to `gasService`. The issue is that `msg.value` may be more than `gasValue`. The excess ETH would stay in ITS and will likely be used by other users to fund their transfers.
Consider, refunding any excess ETH back to the caller.

### [L-05] WETH and USDB Blast yield will be lost

If WETH or USDB are used in the ITS, deployed on Blast, their accumulated yield will not be claimable. By default the yield strategy for WETH and USDB on Blast is AUTOMATIC, thus their smart contract balances automaically grow. Therefore, if USDB or WETH are locked in a TokenManager, deployed on Blast, they will accrue yield, which cannot be claimed.
Consider implementing a special TokenManger for Blast that configures it's strategy to Claimable and has a function that handles accrued yield