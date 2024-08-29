## Finding 1: Missing override Keyword in Overriding Functions

Impact: 
Contracts that inherit from an interface or parent contract must include the override keyword in functions that are meant to override those in the inherited interface or contract. Failing to include this keyword causes the Solidity compiler to produce an error, preventing the contract from being compiled. This can lead to delays in deployment, functionality issues, and potential downtime in critical systems that depend on these contracts.
Issue Type: Solidity Coding Standard Violation

Description:

When a contract inherits from a parent contract or implements an interface, any functions that are intended to override the parent or interface functions must include the override keyword. This keyword is mandatory in Solidity to ensure that the developer explicitly acknowledges that the function is overriding a base function. The absence of the override keyword causes a compilation error, which can prevent the contract from being deployed or used.

Proof of Concept:

Consider the following contract that implements an interface or inherits from a parent contract:
```sol

interface IAxelarAmplifierGateway is IBaseAmplifierGateway, IBaseWeightedMultisig, IUpgradable {
...
function transferOperatorship(address newOperator) external;
}

contract AxelarAmplifierGateway {
...
 function transferOperatorship(address newOperator) external onlyOperatorOrOwner {
        _transferOperatorship(newOperator);
    }
```

In the above code, the transferOperatorship in the AxelarAmplifierGateway contract is overriding the function in IAxelarAmplifierGateway. However, it lacks the override keyword, which will result in a compilation error.

Mitigation:

The solution is to add the override keyword to all functions in the derived contract that are intended to override functions in an interface or parent contract. Below is the corrected version of the contract:
```sol
function transferOperatorship(address newOperator) external onlyOperatorOrOwner override {
        _transferOperatorship(newOperator);
    }
```

The addition of the override keyword ensures that the contract acknowledges and correctly overrides the function from the parent contract or interface, allowing the contract to compile successfully.

## Finding 2: Pragma version for all contracts must be updated from ^0.8.0 to ^0.8.4 in order for all contracts to compile successfully.

Issue Type: Compilation / Compatibility

Description:

The Solidity compiler has undergone several updates between versions 0.8.0 and 0.8.4. These updates include important bug fixes and optimisations that may affect the behaviour and security of the smart contracts. The current contracts use pragma solidity ^0.8.0, which could allow them to be compiled with a version that lacks these important updates.

Ensuring that the contracts are compiled with at least version 0.8.4 minimises the risk of encountering known issues that were present in earlier versions of Solidity 0.8.x, leading to more secure and reliable contract behaviour.

Impact:

If the contracts are compiled with a version of Solidity between 0.8.0 and 0.8.3, they might be vulnerable to bugs and issues that were addressed in version 0.8.4. This could lead to unexpected behaviour, security vulnerabilities, or even compilation errors in certain cases, compromising the integrity of the deployed smart contracts.

Proof of Concept:

Given the following example AxelarAmplifierGateway.sol contract:
```sol
// https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L3

pragma solidity ^0.8.0;
```

If compiled with Solidity 0.8.0, it will error as it needs to be of version ^0.8.4 to compile successfully.

Mitigation:

Update the pragma directive to enforce the use of Solidity 0.8.4 or later across all contracts. This ensures it compiles and that the contracts benefit from the bug fixes and optimisations available in Solidity 0.8.4.

Updated Contract Example:
```sol
pragma solidity ^0.8.4;
```

By updating the pragma directive to ^0.8.4, we ensure that the contract is compiled with a Solidity version that includes all necessary fixes and optimisations, reducing the risk of security issues or bugs related to older versions.