# Title
`state::update_token_balance` in interchain-token-service reports an incorrect error

## Description
In case of an underflow, the error is wrongly reported as `Error::MissingConfig`. Instead the error reported should be `Error::InsufficientBalance`.

```solidity
pub fn update_token_balance(
    storage: &mut dyn Storage,
    token_id: TokenId,
    chain: ChainName,
    amount: Uint256,
    is_deposit: bool,
) -> Result<(), Error> {
    let key = TokenChainPair { token_id, chain };

    let token_balance = TOKEN_BALANCES.may_load(storage, key.clone())?;

    match token_balance {
        Some(TokenBalance::Tracked(balance)) => {
            let token_balance = if is_deposit {
                balance
                    .checked_add(amount)
                    .map_err(|_| Error::MissingConfig)?
            } else {
                balance
                    .checked_sub(amount)
                    .map_err(|_| Error::MissingConfig)? //@audit -> wrong error 
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
        Some(_) | None => (),
    }

    Ok(())
}
```  