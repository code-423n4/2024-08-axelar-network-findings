# L-01
## Title
Reverting the validation of signatures when the threshold is reached and there are more signatures left

## Vulnerability Details
When validating the signatures to verify if enough signers signed the provided message, when the total weight accumulated on the valid signatures reaches the threshold, [there is a validation to determine if all the signatures were used or if there are any unchecked signatures](https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol?vscode-lang=es-419#L221-L226), and in case that there are unchecked signatures the execution is reverted.
This is not a good approach since there is no point in reverting the execution because the threshold has already been reached, even though there are more signatures, at this point, those extra signatures don't matter, whether they are valid or invalid, the threshold has been reached with the current number of valid signatures.


## Impact
Reverting transactions when they should not be reverted and the execution should be allowed.

## Tools Used
Manual Audit

## Recommendations
Remove the internal logic inside the if when the threshold is reached, only return the execution, there is no need to do anything else.

```
function _validateSignatures(
    ...
) internal pure {
    ...
    for (uint256 i; i < signaturesLength; ++i) {
        ...

        // weight needs to reach threshold
        if (totalWeight >= weightedSigners.threshold) {
-           // validate the proof if there are no redundant signatures
-           if (i + 1 == signaturesLength) return;

-           revert RedundantSignaturesProvided(i + 1, signaturesLength);
+           return;
        }

        ...
    }

    ...
    }
```
------
# L-02
## Title
symbol() that returns bytes32 instead of string causes execution to revert when deploying a remote canonical interchain token

## Vulnerability Details
When deploying a RemoteCanonicalInterChainToken on the InterchainTokenFactory, [the symbol() of the token is called and is assigned to a string variable](https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/InterchainTokenFactory.sol#L290).
The problem is that some ERC-20 tokens do not return a string as a value, instead, they return a bytes32, for example, the [MKR token](https://etherscan.io/address/0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2#readContract#F7).
- This would cause an ABI decoding to revert, ultimately reverting the tx, making it impossible to deploy a canonical remote token for those types of tokens.

## Impact
It is not possible to deploy a RemoteCanonicalToken for ERC-20 tokens that returns bytes32 instead of string as a symbol

## Tools Used
Manual Audit & [Solodit Report](https://solodit.xyz/issues/m-04-safesymbol-can-revert-causing-dos-code4rena-timeswap-timeswap-git)

## Recommendations
Use the BoringCrypto safeSymbol() function code with the returnDataToString() parsing function to handle the case of a bytes32 return value: https://github.com/boringcrypto/BoringSolidity/blob/ccb743d4c3363ca37491b87c6c9b24b1f5fa25dc/contracts/libraries/BoringERC20.sol#L15-L39

------
# L-03
## Title
hardcoded bytecodehash in Create3AddressFixed contract on in the interchain-token-service repository doesn't match the bytecode of the Create3AddressFixed contract from the axelar-gmp-sdk-solidity repo

## Vulnerability Details
The [bytecode assigned as a constant for the Deploy contract in the variable CREATE_DEPLOY_BYTECODE](https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/utils/Create3AddressFixed.sol#L13-L14) doesn't match the bytecodehash of the CreateDeploy contract from the axelar-gmp-sdk-solidity repo.
This discrepancy may be caused by some updated on the CreateDeploy contract that did not exist when the bytecodehash of the CREATE_DEPLOY_BYTECODE was generated.

Find below a PoC to demonstrate the two bytecodehash are different.

It'll be required to set up a foundry project and import the [`CreateDeploy.sol`](https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/deploy/CreateDeploy.sol) & [`Create3Address.sol`](https://github.com/code-423n4/2024-08-axelar-network/blob/main/axelar-gmp-sdk-solidity/contracts/deploy/Create3Address.sol) contracts into a new test file where the below test needs to be copied.

<details>
<summary><b>Expand to reveal PoC</b></summary>
<br>

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Create3Address } from './Create3Address.sol';
import { CreateDeploy } from './CreateDeploy.sol';

import {Test, console} from "forge-std/Test.sol";


// TokenTransferTest is a contract that sets up and runs the test
contract VerifyByteCode is Test {

    bytes internal constant CREATE_DEPLOY_BYTECODE =
        hex'608060405234801561001057600080fd5b50610162806100206000396000f3fe60806040526004361061001d5760003560e01c806277436014610022575b600080fd5b61003561003036600461007b565b610037565b005b8051602082016000f061004957600080fd5b50565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60006020828403121561008d57600080fd5b813567ffffffffffffffff808211156100a557600080fd5b818401915084601f8301126100b957600080fd5b8135818111156100cb576100cb61004c565b604051601f8201601f19908116603f011681019083821181831017156100f3576100f361004c565b8160405282815287602084870101111561010c57600080fd5b82602086016020830137600092810160200192909252509594505050505056fea264697066735822122094780ce55d28f1d568f4e0ab1b9dc230b96e952b73d2e06456fbff2289fa27f464736f6c63430008150033';
    bytes32 internal constant CREATE_DEPLOY_BYTECODE_HASH = keccak256(CREATE_DEPLOY_BYTECODE);

    Create3Address create3Contract;

    // setUp function runs before each test, setting up the environment
    function setUp() public {
         create3Contract = new Create3Address();
    }

    function test_VerifyByteCode() external {

      bytes memory creationCode = type(CreateDeploy).creationCode;
      assertEq(creationCode, CREATE_DEPLOY_BYTECODE);

      bytes32 createDeployBytecodeHash = create3Contract.createDeployBytecodeHash();
      assertEq(CREATE_DEPLOY_BYTECODE_HASH, createDeployBytecodeHash);
    }
  
}
```

</details>

Run the PoC and verify that the two bytecodehashes are completely different.
- Command to run the PoC: `forge test --match-test test_VerifyByteCode -vvvv`

## Impact
Potentially using an outdated bytecode for the CreateDeploy contract on the Create3AddressFixed contract

## Tools Used
Manual Audit

## Recommendations
Double-check that the currently hardcoded bytecodehash indeed represents the exact same bytecode for the CreateDeploy contract.


------
# L-04
## Title
Incorrect conditional wrongly reverts txs even though the FlowLimit between tokensIn and tokensOut is not exceeded

## Vulnerability Details
The FlowLimit is defined as the ceiling on the net token flow within a defined epoch [(difference between flow in and out)](https://github.com/axelarnetwork/axelar-docs/blob/main/src/pages/dev/send-tokens/interchain-tokens/rate-limit.mdx#:~:text=Uses%20a%20flow%20limit%2C%20or%20a%20ceiling%20on%20the%20net%20token%20flow%20(difference%20between%20flow%20in%20and%20out)).

## Impact
Tx to bridge tokens [could be wrongly reverted when there is enough FlowLimit to satisfy the requested amount to be bridged](https://github.com/code-423n4/2024-08-axelar-network/blob/main/interchain-token-service/contracts/utils/FlowLimit.sol#L105), even though the difference between Ins and Outs is below the FlowLimit.

In the below example, we'll find out that tx would be reverted even though the difference between Ins and Outs is still below the defined FlowLimit.

For example, assuming a new epoch with a FlowLimit of 100.

1) First Operation, 50 tokensIn
- Start of the epoch, 50 tokensIn / 0 tokensOut
    - difference: 50

2) Second Operation, 100 tokensOut
- 50 tokensIn / 100 tokensOut
    - difference: 50

3) Third Operation, 125 tokensIn
- 175 tokensIn / 100 tokensOut
    - difference: 75

```
function _addFlow(uint256 flowLimit_, uint256 slotToAdd, uint256 slotToCompare, uint256 flowAmount) internal {
 ...

 if (flowToAdd + flowAmount > flowToCompare + flowLimit_)
 revert FlowLimitExceeded((flowToCompare + flowLimit_), flowToAdd + flowAmount, address(this));
    
 //@audit => The 3rd operation would revert here, even though the difference between Ins and Outs is 75 (below the FlowLimit), this check will make the tx revert.
 if (flowAmount > flowLimit_) revert FlowLimitExceeded(flowLimit_, flowAmount, address(this));

 ...
}
```

## Tools Used
Manual Audit

## Recommendations
Since flowLimit is the difference between flowIn and flowOut, remove the check `if (flowAmount > flowLimit_)` to allow the flowLimit to be correctly enforced based on the difference between flowsIn and flowsOut.

```
function _addFlow(uint256 flowLimit_, uint256 slotToAdd, uint256 slotToCompare, uint256 flowAmount) internal {
    ...

    if (flowToAdd + flowAmount > flowToCompare + flowLimit_)
        revert FlowLimitExceeded((flowToCompare + flowLimit_), flowToAdd + flowAmount, address(this));
    
-   if (flowAmount > flowLimit_) revert FlowLimitExceeded(flowLimit_, flowAmount, address(this));

    ...
}
```

Or, if the FlowLimit is meant to also limit the amount that can be bridged on each operation, regardless of the amounts bridged on the current epoch, either document this fact, or add a separate variable to define a specific limit per each transaction. In this way, the FlowLimit would limit the difference between flowIn and flowOut, and the new variable (or constant) would limit the amount to bridge on each operation. 