### 1. Primary Key and Prefixer implementation for TokenChainPair concatenate key components withut any delimiter or separator.

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/state.rs#L48-L66

#### Impact

In state.rs the key and prefix functions concatenate the key components without any delimiter or separator, which may lead to key collision issues if the components overlap. 

```rust
impl<'a> PrimaryKey<'a> for TokenChainPair {
    type Prefix = TokenId;
    type SubPrefix = ();
    type Suffix = ChainName;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        let mut keys = self.token_id.key();
        keys.extend(self.chain.key());
        keys
    }
}

impl<'a> Prefixer<'a> for TokenChainPair {
    fn prefix(&self) -> Vec<Key> {
        self.key()
    }
}
```

#### Recommended Mitigation Steps

Consider using a delimiter to separate key components for better key uniqueness.


***

### 2. No way to revoke roles for Minter and Operator roles

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/utils/Operator.sol#L18-L19

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/utils/Minter.sol#L16-L18

#### Impact

Operator.sol and Minter.sol inherit RolesBase.sol which holds the internal `_removeRole` and `_removeRoles` function. These functions are however not exposed in the contracts, and as a result, roles cannot be revoked by anyone. Also, due to the absence of a centralized admin system, and the function to relinquish privileges, the old privileged roles cannot be revoked.If these roles are compromised, further losses cannot be prevented by revoking their authorization.


```solidity
contract Operator is IOperator, RolesBase, RolesConstants {
```

```solidity
contract Minter is IMinter, RolesBase, RolesConstants {
```

#### Recommended Mitigation Steps

Recommend introducing a centralized admin, and the exposing the functions to revoke roles.

***

### 3. Function to remove trusted address is not exposed and as such trusted address cannot be remove

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/state.rs#L121-L130

#### Impact

state.rs declares the `remove_trusted_address` function to be called in context of the same crate. However, in the outer facing [contract.rs ](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/contract.rs)the a function that calls it is not declared, nor is a message type like that declared as such, trusted address cannot be removed. 

```rust
pub(crate) fn remove_trusted_address(
    storage: &mut dyn Storage,
    chain: &ChainName,
) -> Result<(), Error> {
    TRUSTED_ITS_ADDRESSES.remove(storage, chain);
    Ok(())
}
```


#### Recommended Mitigation Steps

Recommend creating a message type and exposing the function. Or conversely removing it since it doesn't seem to be in use in the codebase.

***

### 4. `increment_msg_counter` is u32 param which gives limitied counter amount before overflow dos

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/contracts/axelarnet-gateway/src/state.rs#L160-L163

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/packages/axelar-wasm-std/src/counter.rs#L23-L31

#### Impact

`increment_msg_counter` uses u32 parameter which can get get exhauseted in a matter of uses as the limit is a little over four billion. Depending on how heavy the protcol is used to transfer messages, this limit can be easily exhaused. Important to note that since one of the functions that query it has open permission, it can be exhausted easily by potential spams, especially in a cooordinated effort.

```rust
pub(crate) fn increment_msg_counter(storage: &mut dyn Storage) -> Result<u32, Error> {
    COUNTER.incr(storage).map_err(Error::from)
}
```

When the limit is reached, the calls to the function will always revert due to overflow, causing a permanent dos of protcol operations.

#### Recommended Mitigation Steps

Recommend using the u128 param instead, since it allows for much larger values.
***

### 5. Remove unused test declaration

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/state.rs#L121-L122

#### Impact
In state.rs the test declaration is made despite tests not being introduced after it. It's actually done twice [here](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/state.rs#L121) and [here](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/state.rs#L211)

```rust
#[cfg(test)]
pub(crate) fn remove_trusted_address(
```

***

### 6. Redundant check for signature weights in `_validateSignatures`

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol#L203

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol#L233

#### Impact

`_validateSignatures` first checks if the `signaturesLength` is 0, executes the loop, then reverts again if weight sum is below threshold. The first check is not needed, because if `signaturesLength` is 0, the loop will automatically be skipped and the function will revert anyway with the `LowSignaturesWeight` error.

```solidity
    function _validateSignatures(
        bytes32 messageHash,
        WeightedSigners calldata weightedSigners,
        bytes[] calldata signatures
    ) internal pure {
//...
        if (signaturesLength == 0) revert LowSignaturesWeight();
//...
        for (uint256 i; i < signaturesLength; ++i) {
//...
        }

        // if weight sum below threshold
        revert LowSignaturesWeight();
    }
```

#### Recommended Mitigation Steps

Consider removing the `if (signaturesLength == 0) revert LowSignaturesWeight();` check, since its not needed.
***

### 7. ITS contract.rs doesn't set new contract version during migration

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/contract.rs#L42-L51

#### Impact

When the `migrate` function is queried in contract.rs, a new contract name and version is not set. As a result, the new implementation will hold the same name and version as previous implementation contrary to how it should be.
```rust
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // Implement migration logic if needed
    Ok(Response::default())
}

```

Add this test to [contract.rs](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/contract.rs). It fails because there's no contract name set after migration.

```rs
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    use super::*;

    #[test]
    fn migrate_doesnt_sets_contract_version() {
        let mut deps = mock_dependencies();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
       assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
```

To show that it uses the previous contract version even after migration, add this test to [contract.rs](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/interchain-token-service/src/contract.rs). It should pass with the newly migrated implementation having the same name and version as the previous.

```rs
#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    use super::*;

    #[test]
    fn migrate_uses_previous_contract_version() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);

        // Initialize the contract
        let msg = InstantiateMsg {
            chain_name: "source-chain".parse().unwrap(),
            gateway_address: "gateway".to_string(),
            trusted_addresses: None,
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);


        migrate(deps.as_mut(), env.clone(), Empty {}).unwrap();

        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
```


#### Recommended Mitigation Steps

Recommend calling the `set_contract_version` in the `migrate` function.
***

### 8. Users cannot burn their own tokens

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L127-L130

#### Impact

The burn function requires the minter role to be able to burn tokens from a user. However, there's no function for a user to burn his own tokens. While it sounds counterintuitive, certain protocol implementations may sometimes reequire directly burning the tokens they hold to execute certain functions, and the current Interchain token's implementation doesn't allow for that. Granting such protocols minter role might be a serious access control risk. 

```solidity
    function burn(address account, uint256 amount) external onlyRole(uint8(Roles.MINTER)) {
        _burn(account, amount);
    }
```


#### Recommended Mitigation Steps

Recommend introducing another burn function open to any user, with which msg.sender's tokens can be burned.
```solidity
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
```
***

### 9. ERC20 permit signatures cannot be cancelled before their expiry

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/ERC20Permit.sol#L78-L84

#### Impact

The `permit` signatures in ERC20Permit.sol offers the signer the option to create a EIP-712 signature. After signing this signature, a signer might want to cancel it, but will not be able do so. This is because there is no function to increase nonce is not exposed as the `nonces[issuer]++` mechanism is used instead.


```solidity
    function permit(address issuer, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert PermitExpired();
//...
        bytes32 digest = keccak256(
            abi.encodePacked(
                EIP191_PREFIX_FOR_EIP712_STRUCTURED_DATA,
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_SIGNATURE_HASH, issuer, spender, value, nonces[issuer]++, deadline))
            )
        );
//...
    }
```

#### Recommended Mitigation Steps

Consider introducing an external function like `IncreaseNonce` that increase the nonce on behalf of the `issuer`/`msg.sender`.

***

### 10. Implementations of `transferFrom` and `_spendAllowance` may not require approval from owner.

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/ERC20.sol#L83-L85

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L135-L141

#### Impact


ERC20.sol's implementation of `transferFrom` may allow the token owner to not need approval before transferring. This can help cut down on unnecessary approvals for owners and smart contracts that use the "pull" method to transfer tokens.

```solidity
    function transferFrom(address sender, address recipient, uint256 amount) external virtual override returns (bool) {
        uint256 _allowance = allowance[sender][msg.sender];

        if (_allowance != UINT256_MAX) {
            _approve(sender, msg.sender, _allowance - amount);
        }
//...
    }

```

The same can be obesrved in the `_spendAllowance` function in InterchainToken.sol

```solidity
    function _spendAllowance(address sender, address spender, uint256 amount) internal override {
        uint256 _allowance = allowance[sender][spender];

        if (_allowance != UINT256_MAX) {
            _approve(sender, spender, _allowance - amount);
        }
    }
```


#### Recommended Mitigation Steps

Use this

```solidity
        if (_allowance != UINT256_MAX || spender == sender) {
            _approve(sender, spender, _allowance - amount);
       }
```
***

### 11. Direct deployment of InterchainToken risks a nameless, permisssionless, potentially useless token being deployed. Recommend calling the init fxn inside the constructor too.

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L35-L43

#### Impact

InterchainToken.sol, when deployed direclty initializes the contract and sets the ITS address. Since its an ERC20, interchain token, we'd at least expect it to have certain important features with which it can be identified, but these are not set in the constructor. They're handled by the `init` function instead.

```solidity
    constructor(address interchainTokenServiceAddress) {
        _initialize();

        if (interchainTokenServiceAddress == address(0)) revert InterchainTokenServiceAddressZero();

        interchainTokenService_ = interchainTokenServiceAddress;
    }
```

The issue is that the `init` function checks if the contrasct is already initialized and reverts if it has, which is what would have happended during direct deployment. As a result, we'd be left with a nameless, sybolless, decimalless token, that can't be minted and has no permit functions. Practicaclly useless.
```solidity
    function init(bytes32 tokenId_, address minter, string calldata tokenName, string calldata tokenSymbol, uint8 tokenDecimals) external {
        if (_isInitialized()) revert AlreadyInitialized();

        _initialize();

        if (tokenId_ == bytes32(0)) revert TokenIdZero();
        if (bytes(tokenName).length == 0) revert TokenNameEmpty();
        if (bytes(tokenSymbol).length == 0) revert TokenSymbolEmpty();

        name = tokenName;
        symbol = tokenSymbol;
        decimals = tokenDecimals;
        tokenId = tokenId_;

        /**
         * @dev Set the token service as a minter to allow it to mint and burn tokens.
         * Also add the provided address as a minter. If `address(0)` was provided,
         * add it as a minter to allow anyone to easily check that no custom minter was set.
         */
        _addMinter(interchainTokenService_);
        _addMinter(minter);

        _setNameHash(tokenName);
    }
```
#### Recommended Mitigation Steps

I'd recommend taking in the parameters needed for the `init` function and calling it in the constructor instead of `_initialize`. 
***

### 12. `_spendAllowance` implementation in InterchainToken.sol doesn't match the comment. 

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/interchain-token/InterchainToken.sol#L131-L141

#### Impact

The implemenation is expected to be overwritten but the function is not marked virtual.

```solidity
    /**
     * @notice A method to be overwritten that will decrease the allowance of the `spender` from `sender` by `amount`.
     * @dev Needs to be overwritten. This provides flexibility for the choice of ERC20 implementation used. Must revert if allowance is not sufficient.
     */
    function _spendAllowance(address sender, address spender, uint256 amount) internal override {
        uint256 _allowance = allowance[sender][spender];

        if (_allowance != UINT256_MAX) {
            _approve(sender, spender, _allowance - amount);
        }
    }
```

#### Recommended Mitigation Steps

I'm leaning towarrds the comments being incorrect here, otherwise any attempts to override the function will fail. Recommend updating the comments.

***

### 13. Redundant chcek for permissons, since function permission is open to anyone

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs#L93-L95

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/contracts/axelarnet-gateway/src/msg.rs#L18-L41

#### Impact 
`execute` function in contract.rs checks to ensure sender's permissions. This is not needed since the message types are expected to be accessible by any user includng admins as can be seen from the [ExecuteMsg](https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-amplifier/contracts/axelarnet-gateway/src/msg.rs#L18C1-L41C1) enum.
```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let msg = msg.ensure_permissions(deps.storage, &info.sender)?;
//...
    match msg {
        ExecuteMsg::CallContract {
//...
        ExecuteMsg::RouteMessages(msgs) => {
//...
        ExecuteMsg::Execute { cc_id, payload } => {
//...
}
```

#### Recommended Mitigation Steps

The check for permissions can be safely removed.
***

### 14. `isCommandExecuted` returns true even for approved messages

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/gateway/BaseAmplifierGateway.sol#L115-L117

#### Impact

The `isCommandExecuted` function returns true if the message is not "MESSAGE_NONEXISTENT". However, since there are three message types, `MESSAGE_NONEXISTENT`, `MESSAGE_EXECUTED` and a hash of the message indicating that the message has been approved, this error means that an approved not executed message will return true. This provides wrong information to any dependencies.

```solidity
    function isCommandExecuted(bytes32 commandId) public view override returns (bool) {
        return _baseAmplifierGatewayStorage().messages[commandId] != MESSAGE_NONEXISTENT;
    }
```

#### Recommended Mitigation Steps

Recommend just checking that the message is executed directly.


```diff
    function isCommandExecuted(bytes32 commandId) public view override returns (bool) {
-        return _baseAmplifierGatewayStorage().messages[commandId] != MESSAGE_NONEXISTENT;
+        return _baseAmplifierGatewayStorage().messages[commandId] == MESSAGE_EXECUTED;
    }
```
***
### 15. Consider using two step to transfer roles

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L132-L145

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/token-manager/TokenManager.sol#L131-L133

#### Impact

The operator address carries numerous important abilities for the system. However AxelarAmplifierGateway.sol directly uses the `transferOperatorship` function which can allow the admin address to be errantly transferred to the wrong address as it does not use a two-step transfer process.

```solidity
    function transferOperatorship(address newOperator) external onlyOperatorOrOwner {
        _transferOperatorship(newOperator);
    }

    /**********************\
    |* Internal Functions *|
    \**********************/

    function _transferOperatorship(address newOperator) internal {
        _axelarAmplifierGatewayStorage().operator = newOperator;

        emit OperatorshipTransferred(newOperator);
    }
```

The same can also be observed in FlowLimiter.sol in the `transferFlowLimiter` function which also uses one step.

```solidity
    function transferFlowLimiter(address from, address to) external onlyRole(uint8(Roles.OPERATOR)) {
        _transferAccountRoles(from, to, 1 << uint8(Roles.FLOW_LIMITER));
    }
```

#### Recommended Mitigation Steps

Consider implementing a two step method, like that of the `propose` and `accept` methods as can be see in Operator.sol and Minter.sol
***


### 16. Contract owner while being trusted/permissioned cannot rotate signers without enforcing rotation delay

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L96-L107

#### Impact

Even though the contract owner arguably has more permissions and is more important than the operator, he can't call `rotateSigners` function without the function enforcing delay. This is due to the bool that sets `enforceRotationDelay` to true if the caller is not the operator. As a result, the owner calling the function will also be limited by the delay time.

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

#### Recommended Mitigation Steps
I'd recommend also allowing the owner to be able to rotate signers without the delay being put into effect.
***

### 17. Redundant comparison when handling fee

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/TokenHandler.sol#L195-L203

#### Impact

`_transferTokenFromWithFee` transfers tokens and checks the `balanceOf` after and before using the param `diff`. It then compares if the `diff` is less than `amount` being transferred, sets it as `amount` and returns it. 

The comparison is unnecessary as `diff` can be set as `amount` regardless as if no fee is charged, `diff` will still be equal to `amount`, and realistically, `diff` can never be more than `amount`.

```solidity
    function _transferTokenFromWithFee(
        address tokenAddress,
        address from,
        address to,
        uint256 amount
    ) internal noReEntrancy returns (uint256) {
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(to);

        _transferTokenFrom(tokenAddress, from, to, amount);

        uint256 diff = IERC20(tokenAddress).balanceOf(to) - balanceBefore;
        if (diff < amount) {
            amount = diff;
        }

        return amount;
    }
```

#### Recommended Mitigation Steps

```diff
    function _transferTokenFromWithFee(
        address tokenAddress,
        address from,
        address to,
        uint256 amount
    ) internal noReEntrancy returns (uint256) {
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(to);

        _transferTokenFrom(tokenAddress, from, to, amount);

        uint256 diff = IERC20(tokenAddress).balanceOf(to) - balanceBefore;
-        if (diff < amount) {
            amount = diff;
-        }

        return amount;
    }
```
***

### 18. Initially minted tokens are not sent to minter contrary to the comments

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L124

https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L151

#### Impact

According to the comments on `deployInterchainToken`, the minter is the address that the initially minted tokens are sent to.

```solidity
     * @param initialSupply The amount of tokens to mint initially (can be zero).
     * @param minter The address to receive the initially minted tokens.
     * @return tokenId The tokenId corresponding to the deployed InterchainToken.
     */
```
But contrary to the implementation, the initially minted tokens are sent to msg.sender rather than the minter.

```solidity
    function deployInterchainToken(
        bytes32 salt,
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        uint256 initialSupply,
        address minter
    ) external payable returns (bytes32 tokenId) {
//...
            token.mint(sender, initialSupply);

//...
    }
```

***

### 19. `_approveGateway` should not check if allowance is 0

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/contracts/TokenHandler.sol#L225-L230

#### Impact

`_approveGateway` checks if allowance is 0, and if 0, approves the amount to the gateway. This means, if the gateway has an allowance already greater than 0, even if its just 1 wei, attempts to approve the gateway will fail. This is very unlikely to happen though.

```solidity
    function _approveGateway(address tokenAddress, uint256 amount) internal {
        uint256 allowance = IERC20(tokenAddress).allowance(address(this), gateway);
        if (allowance == 0) {
            IERC20(tokenAddress).safeCall(abi.encodeWithSelector(IERC20.approve.selector, gateway, amount));
        }
    }
```

#### Recommended Mitigation Steps

I'd recommend checking if allowance is less than amount instead.
```diff
    function _approveGateway(address tokenAddress, uint256 amount) internal {
        uint256 allowance = IERC20(tokenAddress).allowance(address(this), gateway);
-        if (allowance == 0) {
+        if (allowance < amount) {
            IERC20(tokenAddress).safeCall(abi.encodeWithSelector(IERC20.approve.selector, gateway, amount));
        }
    }
```
***

### 20. `domainSeparator` is immutable and set in constructor

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L30-L34

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol#L44-52

#### Impact

In AxelarAmplifierGateway.sol, the `domainSeparator` is set in the constructor. It's also declared in BaseWeightedMultisig.sol 

```solidity
    constructor(
        uint256 previousSignersRetention_,
        bytes32 domainSeparator_,
        uint256 minimumRotationDelay_
    ) BaseWeightedMultisig(previousSignersRetention_, domainSeparator_, minimumRotationDelay_) {}

```

```solidity
    constructor(
        uint256 previousSignersRetention_,
        bytes32 domainSeparator_,
        uint256 minimumRotationDelay_
    ) {
        previousSignersRetention = previousSignersRetention_;
        domainSeparator = domainSeparator_;
        minimumRotationDelay = minimumRotationDelay_;
    }
```
Thia means that it can't be changed. Idealy, this wouldn't be an issue, but the contracts  is going to be deployed on [various chains](https://axelarscan.io/resources/chains)  and  doesn't take into account that the chain to which the protocol would be deployed could undergo a hardfork, which would then make the block.chainId attached to domainseparator to now be stale. As a result, signatures can be replayed across chains.

#### Recommended Mitigation Steps

Recommend not declaring it in the constructor.
***


### 21. Solidity version ^0.8.23 won't work on all chains due to MCOPY 

Links to affected code *

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/axelar-gmp-sdk-solidity/hardhat.config.js#L39

https://github.com/code-423n4/2024-08-axelar-network/blob/c383cc0e51805357bca8741ec5d1568cacbff6cc/interchain-token-service/hardhat.config.js#L38

#### Impact


Solidity version 0.8.23 introduces the MCOPY opcode, this may not be implemented on all chains and L2 thus reducing the portability and compatibility of the code. The protocol is expected to be deloyed on [various chains](https://axelarscan.io/resources/chains)  and as a result, deployment may fail on these chains.

```js
    version: '0.8.24',
```


```js
    version: '0.8.23',
```

#### Recommended Mitigation Steps

Consider using a earlier solidity version.

***

### 22. Contracts will be deployed on blast but hasn't perform the needed configurations.

Links to affected code *

https://axelarscan.io/resources/chains 

#### Impact

The contracts are to be deployed on blast, an EVM compatible layer 2 chain known for claiming yields and gas fees. This is because its one of the supported chains on axelarscan. 
Blast redirects sequencer or gas fees to the dapps that induced them, allowing smart contract developers to have an additional source of revenue. Since these contracts are to be used for by lots of users, it can be expected that functions inside the contracts will be spending a lot of gas. This can be beneficial to the developers as they can have additional revenue. However, the contracts implementation are not configured to take advantage of blast's features on claiming gas fees. This can be a lost of opportunity to earn potential income from the usage of the contracts.

#### Recommended Mitigation Steps

The contracts should implement the procedure from [Blast Docs](https://docs.blast.io/building/guides/gas-fees) on how to properly claim gas fees.
