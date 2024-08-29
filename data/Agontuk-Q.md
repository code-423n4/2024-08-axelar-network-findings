| Issue ID | Issue Name                                                                 |
|----------|----------------------------------------------------------------------------|
| [L-01](#l-01-unprotected-initialization-in-interchaintoken-contract-allows-front-running)     | Unprotected initialization in InterchainToken contract allows front-running|
| [L-02](#l-02-silent-failures-in-stateupdate_token_balance-for-untracked-or-non-existent-tokens)     | Silent failures in `State::update_token_balance()` for untracked or non-existent tokens|
| [L-03](#l-03-incorrect-error-handling-in-statestart_token_balance-function-may-lead-to-silent-failures)     | Incorrect error handling in `State::start_token_balance()` function may lead to silent failures|
| [L-04](#l-04-incorrect-error-handling-in-stateupdate_token_balance-may-lead-to-confusion)     | Incorrect error handling in `State::update_token_balance()` may lead to confusion|
| [L-05](#l-05-insufficient-handling-of-receivefromhub-messages-in-stateexecute_message-function)     | Insufficient handling of ReceiveFromHub messages in `State::execute_message()` function|
| [L-06](#l-06-potential-duplicate-token-initialization-and-trusted-address-conflicts)     | Potential duplicate token initialization and trusted address conflicts     |




## [L-01] Unprotected initialization in InterchainToken contract allows front-running

## Vulnerability Detail

The `InterchainToken` contract's `init()` function, responsible for setting crucial contract parameters, lacks proper access control. This allows any external actor to call the function and initialize the contract, potentially front-running the legitimate initialization transaction.

The vulnerability stems from the `init()` function being `external` and only protected by an `_isInitialized()` check:

```solidity
function init(bytes32 tokenId_, address minter, string calldata tokenName, string calldata tokenSymbol, uint8 tokenDecimals) external {
    if (_isInitialized()) revert AlreadyInitialized();
    _initialize();
    // ... (initialization logic)
}
```

While this prevents multiple initializations, it doesn't ensure that only authorized parties can perform the initial setup. An attacker could monitor the mempool for the legitimate initialization transaction and front-run it with their own parameters.

## Recommendation

Implement proper access control for the `init()` function. Consider adding an `onlyDeployer` modifier or similar mechanism to ensure only the contract deployer can initialize the contract:

```solidity
address private immutable deployer;

constructor(address interchainTokenServiceAddress) {
    deployer = msg.sender;
    // ... (existing constructor code)
}

function init(bytes32 tokenId_, address minter, string calldata tokenName, string calldata tokenSymbol, uint8 tokenDecimals) external {
    require(msg.sender == deployer, "Unauthorized");
    if (_isInitialized()) revert AlreadyInitialized();
    _initialize();
    // ... (rest of the initialization code)
}
```

This change ensures that only the contract deployer can call the `init()` function, preventing unauthorized initialization and potential front-running attacks.





## [L-02] Silent failures in `State::update_token_balance()` for untracked or non-existent tokens

## Vulnerability Detail

The `update_token_balance()` function in the `state.rs` file silently ignores cases where the token balance is either untracked or non-existent (i.e., `None`). This behavior can lead to unexpected results, as the function returns `Ok(())` without performing any balance update or notifying the caller of the failure.

Specifically, in the following code block:

```rust
match token_balance {
    Some(TokenBalance::Tracked(balance)) => {
        // Balance update logic
    }
    Some(_) | None => (),
}
```

The `Some(_) | None` case, which covers both untracked and non-existent tokens, does nothing and allows the function to return successfully. This can mislead callers into believing that a balance update was performed when it wasn't.

## Recommendation

Modify the `update_token_balance()` function to handle untracked and non-existent token cases explicitly. Return an appropriate error in these scenarios to ensure the caller is aware that the balance update did not occur. For example:

```rust
match token_balance {
    Some(TokenBalance::Tracked(balance)) => {
        // Existing balance update logic
    }
    Some(TokenBalance::Untracked) => {
        return Err(Error::UntrackedToken { token_id, chain });
    }
    None => {
        return Err(Error::TokenNotFound { token_id, chain });
    }
}
```

Additionally, consider adding new error types to the `Error` enum to represent these specific cases.



## [L-03] Incorrect error handling in `State::start_token_balance()` function may lead to silent failures

## Vulnerability Detail

The `start_token_balance()` function in the contract incorrectly uses the `then` method to handle the `Result` returned by `TOKEN_BALANCES.save()`. This is not a standard method for chaining `Result` operations in Rust and can lead to unexpected behavior.

Specifically, the problematic code is:

```rust
TOKEN_BALANCES
    .save(storage, key, &initial_balance)?
    .then(Ok)
```

This incorrect error handling could result in silent failures where the function appears to succeed but does not actually save the token balance. This may cause inconsistencies in the contract's state, potentially affecting other functions that rely on this data.

## Recommendation

Remove the incorrect use of the `then` method and handle the `Result` properly. Update the function to:

```rust
TOKEN_BALANCES.save(storage, key, &initial_balance).map_err(Error::from)
```

This change ensures that any errors from the `save` operation are properly converted to the `Error` type and propagated, maintaining consistent error handling throughout the contract.





## [L-04] Incorrect error handling in `State::update_token_balance()` may lead to confusion

## Vulnerability Detail

The `update_token_balance()` function in the contract incorrectly handles the error case for insufficient balance during token withdrawals. When a withdrawal amount exceeds the current balance, the function returns `Error::MissingConfig` instead of an appropriate insufficient balance error. This can lead to confusion for users and developers interacting with the contract, as the error message does not accurately reflect the nature of the issue.

## Recommendation

Modify the `update_token_balance()` function to return a more appropriate error when the balance is insufficient for a withdrawal. Consider adding a new error type specifically for insufficient balance cases. For example:

```rust
pub fn update_token_balance(
    storage: &mut dyn Storage,
    token_id: TokenId,
    chain: ChainName,
    amount: Uint256,
    is_deposit: bool,
) -> Result<(), Error> {
    let key = TokenChainPair { token_id, chain: chain.clone() };

    TOKEN_BALANCES.update(storage, key, |token_balance| -> Result<_, Error> {
        match token_balance {
            Some(TokenBalance::Tracked(balance)) => {
                let new_balance = if is_deposit {
                    balance.checked_add(amount).ok_or(Error::Std(StdError::overflow()))?
                } else {
                    if balance < amount {
                        return Err(Error::InsufficientBalance {
                            token_id,
                            chain,
                            balance,
                        });
                    }
                    balance.checked_sub(amount).unwrap()
                };
                Ok(TokenBalance::Tracked(new_balance))
            }
            Some(TokenBalance::Untracked) => Ok(TokenBalance::Untracked),
            None => Err(Error::Std(StdError::not_found("Token balance not found"))),
        }
    })?;

    Ok(())
}
```

This change will provide clearer error messages and improve the overall robustness of the contract.




## [L-05] Insufficient handling of ReceiveFromHub messages in `State::execute_message()` function

## Vulnerability Detail

The `execute_message()` function in the contract does not properly handle `ItsHubMessage::ReceiveFromHub` messages. Currently, the function only processes `ItsHubMessage::SendToHub` messages, while any other message type, including `ReceiveFromHub`, results in an `Error::InvalidPayload`. This could potentially lead to missed updates or incorrect state changes if `ReceiveFromHub` messages are expected to be processed by this function.

The relevant part of the `execute_message()` function:

```rust
match its_hub_message {
    ItsHubMessage::SendToHub { ... } => {
        // Handling for SendToHub
    },
    _ => Err(report!(Error::InvalidPayload)),
}
```

## Recommendation

If `ReceiveFromHub` messages are intended to be handled by the `execute_message()` function, add a specific case for processing these messages. This could include applying balance tracking and emitting appropriate events. For example:

```rust
match its_hub_message {
    ItsHubMessage::SendToHub { ... } => {
        // Existing handling for SendToHub
    },
    ItsHubMessage::ReceiveFromHub { source_chain, message: its_message } => {
        apply_balance_tracking(
            deps.storage,
            source_chain.clone(),
            cc_id.source_chain.clone(),
            &its_message,
        )?;

        Ok(Response::new().add_event(
            ItsContractEvent::ItsMessageReceived {
                source_chain,
                destination_chain: cc_id.source_chain.clone(),
                message: its_message,
            }
            .into(),
        ))
    },
    _ => Err(report!(Error::InvalidPayload)),
}
```

If `ReceiveFromHub` messages are not intended to be handled by this function, consider adding a comment explaining why only `SendToHub` messages are processed to improve code clarity.





## [L-06] Potential duplicate token initialization and trusted address conflicts

## Vulnerability Detail

The `State::apply_balance_tracking()` function does not check if a token is already being tracked before initializing balance tracking. This could lead to multiple initializations of the same token, causing an inconsistent state.

Additionally, the `update_trusted_address()` function does not verify if the new trusted address is already in use by another chain. This could result in the same address being trusted for multiple chains, potentially introducing security risks.

## Recommendation

For `apply_balance_tracking()`, add a check to ensure the token is not already being tracked before initializing:

```rust
if is_token_tracked(storage, &token_id, &destination_chain)? {
    return Err(report!(Error::TokenAlreadyTracked {
        token_id: token_id.clone(),
        chain: destination_chain.clone(),
    }));
}
```

For `update_trusted_address()`, implement a check to prevent duplicate trusted addresses across chains:

```rust
let all_chains = get_all_chains(deps.storage)?;
for existing_chain in all_chains {
    if existing_chain != chain {
        let existing_address = load_trusted_address(deps.storage, &existing_chain)?;
        if existing_address == address {
            return Err(report!(Error::DuplicateTrustedAddress {
                chain: existing_chain,
                address: address.clone(),
            }));
        }
    }
}
```

Implement the necessary helper functions `is_token_tracked()` and `get_all_chains()` to support these checks.