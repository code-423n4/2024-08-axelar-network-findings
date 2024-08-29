# [QA-01] Unchecked Return Value in `approveMessages`
## Description
In the `AxelarAmplifierGateway.so`l contract, the `approveMessages` function calls `_validateProof` without checking its return value. This could lead to a situation where messages are approved even if the proof is invalid, potentially compromising the security of the system.

The current implementation:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L83-L84
```
function approveMessages(Message[] calldata messages, Proof calldata proof) external {
    bytes32 dataHash = keccak256(abi.encode(CommandType.ApproveMessages, messages));

    _validateProof(dataHash, proof);

    _approveMessages(messages);
}
```
The `_validateProof` function is likely designed to return a boolean indicating whether the proof is valid. By not checking this return value, the contract proceeds to approve messages regardless of the proof's validity.
## Recommendation
Modify the `approveMessages` function to check the return value of `_validateProof` and only proceed with message approval if the proof is valid

# [QA-02] Silent Failure in onlySigners Modifier
## Description
The `onlySigners` modifier in the `BaseMultisig` contract silently fails when the voting threshold is not met. Instead of reverting the transaction, it simply returns without executing the function body. This behavior can lead to unexpected results and potential misunderstandings about the contract's state.

Current implementation:
```
modifier onlySigners() {
    if (!_isFinalSignerVote()) return;

    _;
}
```
When `_isFinalSignerVote()` returns false (i.e., when the voting threshold is not met), the modifier simply returns, allowing the transaction to succeed without executing the intended function. This can be misleading, as a successful transaction doesn't necessarily mean the function's logic was executed.
## Recommendation
- Modify the onlySigners modifier to revert when the voting threshold is not met:
```
modifier onlySigners() {
    require(_isFinalSignerVote(), "Voting threshold not met");
    _;
}
```

# [QA-03] Lack of Event for Signer Rotation
## Description
In the `AxelarAmplifierGateway` contract, there are two instances where signer rotation occurs:

- During the setup process in the _setup function:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L63-L64
```
   function _setup(bytes calldata data) internal override {
       // ...
       for (uint256 i = 0; i < signers.length; i++) {
           _rotateSigners(signers[i], false);
       }
   }
```
- In the rotateSigners function:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L106-L107
```
   function rotateSigners(WeightedSigners memory newSigners, Proof calldata proof) external {
       // ...
       _rotateSigners(newSigners, enforceRotationDelay);
   }
```
However, neither of these instances emits an event when signers are rotated. This lack of event emission presents transparency issues, makes it harder to track changes off-chain and is aginst best practices.
## Recommendation
- Implement an event for signer rotation and emit it whenever signers are rotated

# [QA-04] Incomplete Signature Validation in `ERC20Permit.sol`
## Description
The ERC20Permit contract implements signature validation for the `permit` function, but the validation is incomplete. While the contract checks for an upper bound on the 's' value of the signature, it fails to check for a lower bound. Specifically, the current implementation only checks:
```
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidS();
```
This check prevents 's' values greater than half the curve order, which is good practice. However, it doesn't prevent an 's' value of 0, which is never valid in an ECDSA signature. Although the likelihood of exploiting this is extremely low due to the difficulty of generating a valid signature with s = 0, and Ethereum's `ecrecover` would likely prevent any practical attack, implementing a complete check aligns with best practices for signature validation.
## Recommendation
To fully conform to best practices for ECDSA signature verification in Ethereum, implement both upper and lower bound checks for the 's' value

# [QA-05] Non-Specific Error Message for Invalid Account in Transfer Function
## Description
In the `_transfer` function of the ERC20 contract, a single error message `InvalidAccount` is used to handle two distinct error cases: when the sender is the zero address and when the recipient is the zero address. This lack of specificity in the error message can make debugging more difficult and provide less informative feedback to users and integrating systems.

Current implementation:
https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/interchain-token/ERC20.sol#L143-L144
```
function _transfer(address sender, address recipient, uint256 amount) internal virtual {
    if (sender == address(0) || recipient == address(0)) revert InvalidAccount();

    balanceOf[sender] -= amount;
    balanceOf[recipient] += amount;
    emit Transfer(sender, recipient, amount);
}
```
This implementation makes it challenging to determine whether the issue is with the sender or the recipient without additional context or debugging.
## Recommendation
- Use specific error messages for each case
- if using a single error, include parameters to specify the problematic address and its role

# [QA-06] Lack of Role Revocation Mechanism in Operator Contract
## Description
The `Operator.sol` contract provides functionality for transferring and accepting the operator role but lacks a mechanism to revoke this role. This omission could pose operational challenges in scenarios where an operator needs to be removed without immediately transferring the role to another address.

Currently, the contract includes the following role management functions:

- `transferOperatorship`: Allows the current operator to transfer the role to a new address.
- `proposeOperatorship`: Allows the current operator to propose a new operator.
- `acceptOperatorship`: Allows a proposed operator to accept the role.
However, there is no function to simply revoke or remove an operator's role. This limitation reduces the contract's flexibility in managing the operator role, especially in security-sensitive situations where quick removal of an operator might be necessary.
## Recommendation
- Adding a revokeOperatorship function:
```
function revokeOperatorship(address operator) external onlyRole(uint8(Roles.OPERATOR)) {
    require(operator != msg.sender, "Cannot revoke own operatorship");
    _removeRole(operator, uint8(Roles.OPERATOR));
    emit OperatorshipRevoked(operator);
}

event OperatorshipRevoked(address indexed revokedOperator);
```