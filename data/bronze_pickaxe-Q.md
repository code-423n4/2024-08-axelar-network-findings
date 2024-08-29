# [L-01] u32 might be too low for `counter`
## Description
In `call_contract()`, a counter is used:
```rust
pub(crate) fn call_contract(
    store: &mut dyn Storage,
    router: &Router,
    chain_name: ChainName,
    sender: Addr,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {

    let counter = state::increment_msg_counter(store).change_context(Error::InvalidStoreAccess)?;
    //..
}
```

This counter is of size `U32`. The max value of `U32` is **4,294,967,295**. While this is a high number, if the entry costs into using `call_contract` is too low (for example, when going from a cheap_source_chain to another cheap_destination_chain), then a malicious user might spam call this contract such that counter will reach max value.

When `counter` is max value, it will lead to a Denial of Service.
## Recommended Mitigation Steps
Consider using `U64`.

----

# [L-02] Solidity version is incompatible with Immutable

## Description
One of the chains that the new contracts are being deployed to is Immutable:
- https://axelarscan.io/resources/chains?type=evm

If we take a look at the [Immutable Docs](https://axelarscan.io/resources/chains?type=evm), we find the following:
```md
Immutable zkEVM's most recent hard fork brings us in line with Ethereum's Shanghai fork. 
We currently only support Solidity versions **up to and including 0.8.23**. 
Our EVM does not support versions 0.8.24 and beyond that were introduced in the most recent Ethereum hard fork, Dencun. 
This means that if you use `^`, you will pull the latest solidity compiler version that is incompatible with Immutable zkEVM. 
We'll be transitioning to Dencun over the coming year; stay tuned.
```

The in-scope contracts inside `axelar-gmp-sdk-solidity/contracts/governance/` all use:

```javascript
pragma solidity ^0.8.0;
```

These contracts will not be compatible with Immutable. 
