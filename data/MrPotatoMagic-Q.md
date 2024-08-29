# Quality Assurance Report

## [QA-01] Operator would not be able to rotate malicious signer set when previousSignersRetention = 0

As per the comment below, it is possible for previousSignersRetention to be = 0.
```solidity
    /// @dev Previous signers retention. 0 means only the current signers are valid
    /// @return The number of epochs to keep the signers valid for signature verification
    uint256 public immutable previousSignersRetention;
```

Due to this, it may not be possible for the operator to rotate the malicious signer set since the operator would require the malicious signer set's signatures for the proof to pass. Due to this, the protocol could be compromised. Since this indirectly falls into a centralization risk while being a valid attack path as defined by the protocol, where no signer set can be trusted, it is being reported as QA.

Solution: If previousSignersRetention = 0, allow operator to rotate signers without requiring their signstures.

```solidity
 function rotateSigners(WeightedSigners memory newSigners, Proof calldata proof) external {
        bytes32 dataHash = keccak256(abi.encode(CommandType.RotateSigners, newSigners));

        bool enforceRotationDelay = msg.sender != _axelarAmplifierGatewayStorage().operator;
        bool isLatestSigners = _validateProof(dataHash, proof);
        if (enforceRotationDelay && !isLatestSigners) {
            revert NotLatestSigners();
        }

        // If newSigners is a repeat signer set, this will revert
        _rotateSigners(newSigners, enforceRotationDelay);
    }
```

## [QA-02] Function _validateSigners() should ensure weights are distributed correctly

In function _validateSigners, we do not ensure that the first N/2 signers do not hold total weight > threshold. Although this could be handled offchain, it should be checked onchain to ensure there is no centralization risk present.
```solidity
function _validateSigners(WeightedSigners memory weightedSigners) internal pure {
        WeightedSigner[] memory signers = weightedSigners.signers;
        uint256 length = signers.length;
        uint256 totalWeight;

        if (length == 0) revert InvalidSigners();

        // since signers need to be in strictly increasing order,
        // this prevents address(0) from being a valid signer
        address prevSigner = address(0);

        for (uint256 i = 0; i < length; ++i) {
            WeightedSigner memory weightedSigner = signers[i];
            address currSigner = weightedSigner.signer;

            if (prevSigner >= currSigner) {
                revert InvalidSigners();
            }

            prevSigner = currSigner;

            uint256 weight = weightedSigner.weight;

            if (weight == 0) revert InvalidWeights();

            totalWeight = totalWeight + weight;
        }

        uint128 threshold = weightedSigners.threshold;
        if (threshold == 0 || totalWeight < threshold) revert InvalidThreshold();
    }
```

## [QA-03] Delays in signer rotations when operator identifies malicious signer set

Operator cannot reuse a recent signer set's signatures to perform more rotations instead of just one rotation. This slows down the process of removing a malicious signer set that is more recent. 

Solution: When operator is msg.sender and signers are recent ones, consider not using newSigners in the dataHash to allow operator to rotate many signer sets to remove the malicious signer set. With this make sure to introduce a deadline to the signers signatures to ensure the same signatures cannot be misused by operator in the future. 
```solidity
 function rotateSigners(WeightedSigners memory newSigners, Proof calldata proof) external {
        bytes32 dataHash = keccak256(abi.encode(CommandType.RotateSigners, newSigners));

        bool enforceRotationDelay = msg.sender != _axelarAmplifierGatewayStorage().operator;
        bool isLatestSigners = _validateProof(dataHash, proof);
        if (enforceRotationDelay && !isLatestSigners) {
            revert NotLatestSigners();
        }

        // If newSigners is a repeat signer set, this will revert
        _rotateSigners(newSigners, enforceRotationDelay);
    }
```

## [QA-04] EIP-20 spec does not require token, symbol or decimals to be present

When deploying a token, it expects the interchain token to have a name and symbol. According to the EIP-20 spec, these are optional. It is unlikely the name would not be present but the symbol function call should be wrapped with a try catch.
```solidity
File: InterchainTokenFactory.sol
293:         string memory tokenName = token.name();
294:         string memory tokenSymbol = token.symbol();
```