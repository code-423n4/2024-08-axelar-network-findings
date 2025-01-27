---
sponsor: "Axelar Network"
slug: "2024-08-axelar-network"
date: "2025-01-27"
title: "Axelar Network"
findings: "https://github.com/code-423n4/2024-08-axelar-network-findings/issues"
contest: 424
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Axelar Network smart contract system written in Solidity. The audit took place between August 8 — August 26, 2024.

## Wardens

29 Wardens contributed reports to Axelar Network:

  1. [klau5](https://code4rena.com/@klau5)
  2. [0x007](https://code4rena.com/@0x007)
  3. [gjaldon](https://code4rena.com/@gjaldon)
  4. [Bauchibred](https://code4rena.com/@Bauchibred)
  5. [Sparrow](https://code4rena.com/@Sparrow)
  6. [ZanyBonzy](https://code4rena.com/@ZanyBonzy)
  7. [mxuse](https://code4rena.com/@mxuse)
  8. [trachev](https://code4rena.com/@trachev)
  9. [grearlake](https://code4rena.com/@grearlake)
  10. [ayden](https://code4rena.com/@ayden)
  11. [jasonxiale](https://code4rena.com/@jasonxiale)
  12. [Agontuk](https://code4rena.com/@Agontuk)
  13. [bronze\_pickaxe](https://code4rena.com/@bronze_pickaxe)
  14. [solosync6](https://code4rena.com/@solosync6)
  15. [debo](https://code4rena.com/@debo)
  16. [Sisi](https://code4rena.com/@Sisi)
  17. [PolarizedLight](https://code4rena.com/@PolarizedLight) ([ChaseTheLight](https://code4rena.com/@ChaseTheLight) and [Auditor\_Nate](https://code4rena.com/@Auditor_Nate))
  18. [0xStalin](https://code4rena.com/@0xStalin)
  19. [K42](https://code4rena.com/@K42)
  20. [hunter\_w3b](https://code4rena.com/@hunter_w3b)
  21. [kirill\_taran](https://code4rena.com/@kirill_taran)
  22. [MrPotatoMagic](https://code4rena.com/@MrPotatoMagic)
  23. [Trooper](https://code4rena.com/@Trooper)
  24. [fibonacci](https://code4rena.com/@fibonacci)
  25. [Bob](https://code4rena.com/@Bob)
  26. [KupiaSec](https://code4rena.com/@KupiaSec)
  27. [WenResults](https://code4rena.com/@WenResults) ([thekmj](https://code4rena.com/@thekmj) and [3n0ch](https://code4rena.com/@3n0ch))

This audit was judged by [0xsomeone](https://code4rena.com/@0xsomeone).

Final report assembled by [thebrittfactor](https://twitter.com/brittfactorC4).

# Summary

The C4 analysis yielded an aggregated total of 4 unique vulnerabilities. Of these vulnerabilities, 2 received a risk rating in the category of HIGH severity and 2 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 25 reports detailing issues with a risk rating of LOW severity or non-critical.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Axelar Network repository](https://github.com/code-423n4/2024-08-axelar-network), and is composed of 37 smart contracts written in the Solidity programming language and includes 3997 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (2)
## [[H-01] Bridge requests to remote chains where interchain tokens are not deployed can result in DoS attacks](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/43)
*Submitted by [klau5](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/43), also found by [gjaldon](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/34) and [0x007](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/77)*

<https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L112-L135>

<https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/axelar-amplifier/interchain-token-service/src/state.rs#L192>

### Impact

Insufficient balance in the ITSHub prevents bridging, leading to a DoS attack on the bridge.

### Proof of Concept

ITSHub tracks token balances per chain when moving tokens. If the interchain token is not deployed on the destination chain, the balance is uninitialized, and this transaction is not reverted but passed. In other words, token transfer requests are processed normally even if the interchain token is not deployed on the destination chain.

```rust
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
                    .map_err(|_| Error::MissingConfig)?
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
@>      Some(_) | None => (),
    }

    Ok(())
}
```

If the interchain token is not deployed on the destination chain, even if the message is approved, tokens cannot be bridged because the token is not deployed. However, we can consider scenarios where the remote interchain token deployment request is frontrunned. For canonical tokens, anyone can deploy remote interchain tokens, so it's easy to create a scenario where token transfer is requested first, followed by a request to deploy the remote interchain token.

Consider the following example:

1. The token deployer requests remote interchain token deployment to chain B. This will be frontrunned.
2. Front-running (1), a request is made to transfer 100 ether of tokens.
3. ITSHub first executes `ItsMessage::InterchainTransfer`. As the interchain token is not yet deployed on chain B, the balance for chain B remains `None`.
4. ITSHub then processes `ItsMessage::DeployInterchainToken`, initializing the balance of chain B to 0.
5. After the remote interchain token deployment is completed on chain B, the attacker executes `execute` to receive the bridged tokens.

The balance in ITSHub is 0, but there are 100 ether of bridged tokens on chain B. This balance mismatch can cause problems such as DoS. For example, if another user bridges tokens from chain A to B, increasing the ITSHub balance, the attacker can bridge back from B to A, reducing the ITSHub balance. If a user then tries to bridge from B to A again, they won't be able to due to insufficient balance in ITSHub.

### Recommended Mitigation Steps

The problem is allowing bridging to chains where the remote interchain token is not deployed. The implementation of `update_token_balance` should be changed to allow bridging only to chains where the balance has been initialized.

If you don't want to track the balance of the source chain, instead of judging by balance initialization, you should accurately identify the source chain and handle it.

### Assessed type

DoS

**[milapsheth (Axelar) confirmed and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/43#issuecomment-2334749343):**
 > The report is valid. We agree with the Medium severity since assets can't be stolen, and ITS hub can be upgraded easily to fix the balance invariant. We do plan to restrict transfers if the token isn't initialized yet to handle this scenario. As mentioned, it requires more careful tracking of the source chain of the token.

**[0xsomeone (judge) increased severity to High and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/43#issuecomment-2362278336):**
 > The Warden outlines a discrepancy in the token accounting system of the ITS service that would permit a chain that does not yet have an interchain token deployment in it to process messages for it incorrectly.
> 
> The vulnerability stems from the same root cause as submission [#77](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/77), and I believe both descriptions merit a high severity rating. This particular submission directly outlines how funds could be stolen by front-running the deployment of an interchain token and bridging back, thereby causing funds bridged by other users to become "locked" in the attacked chain.

***

## [[H-02] Can block bridge or limit the bridgeable amount by initializing the ITSHub balance of the original chain](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8)
*Submitted by [klau5](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8)*

<https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L176>

<https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenService.sol#L342>

<https://github.com/code-423n4/2024-08-axelar-network/blob/4572617124bed39add9025317d2c326acfef29f1/interchain-token-service/contracts/InterchainTokenFactory.sol#L269>

### Impact

Token deployers can block the token bridge or limit the bridgeable amount without having Operator or FlowLimiter permissions. Especially, Canonical tokens can be attacked by anyone, not just the token register.

### Proof of Concept

ITSHub does not track the balance of the token on the original chain. It only tracks the balance of other chains which is deployed by remote deployment. This is because on the original chain, minters are usually registered to allow token minting, making balance tracking difficult.

```rust
fn apply_balance_tracking(
    storage: &mut dyn Storage,
    source_chain: ChainName,
    destination_chain: ChainName,
    message: &ItsMessage,
) -> Result<(), Error> {
    match message {
        ItsMessage::InterchainTransfer {
            token_id, amount, ..
        } => {
            // Update the balance on the source chain
@>          update_token_balance(
                storage,
                token_id.clone(),
                source_chain.clone(),
                *amount,
                false,
            )
@>          .change_context_lazy(|| Error::BalanceUpdateFailed(source_chain, token_id.clone()))?;

            // Update the balance on the destination chain
@>          update_token_balance(
                storage,
                token_id.clone(),
                destination_chain.clone(),
                *amount,
                true,
            )
@>          .change_context_lazy(|| {
                Error::BalanceUpdateFailed(destination_chain, token_id.clone())
            })?
        }
        // Start balance tracking for the token on the destination chain when a token deployment is seen
        // No invariants can be assumed on the source since the token might pre-exist on the source chain
        ItsMessage::DeployInterchainToken { token_id, .. } => {
@>          start_token_balance(storage, token_id.clone(), destination_chain.clone(), true)
                .change_context(Error::InvalidStoreAccess)?
        }
        ...
    };

    Ok(())
}
```

The balance of token on destination chain is initialized to 0 only when a new token is remotely deployed. And when tokens move, only the balance of the chain where the balance data has been initialized is updated. In normal cases, the balance of the original chain is not tracked.

```rust
pub fn start_token_balance(
    storage: &mut dyn Storage,
    token_id: TokenId,
    chain: ChainName,
    track_balance: bool,
) -> Result<(), Error> {
    let key = TokenChainPair { token_id, chain };

    match TOKEN_BALANCES.may_load(storage, key.clone())? {
        None => {
            let initial_balance = if track_balance {
@>              TokenBalance::Tracked(Uint256::zero())
            } else {
                TokenBalance::Untracked
            };

            TOKEN_BALANCES
                .save(storage, key, &initial_balance)?
                .then(Ok)
        }
        Some(_) => Err(Error::TokenAlreadyRegistered {
            token_id: key.token_id,
            chain: key.chain,
        }),
    }
}

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
@>                  .checked_add(amount)
                    .map_err(|_| Error::MissingConfig)?
            } else {
                balance
@>                  .checked_sub(amount)
                    .map_err(|_| Error::MissingConfig)?
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
@>      Some(_) | None => (),
    }

    Ok(())
}
```

However, there is a way to initialize the ITSHub balance of the original chain. When initializing the balance, it is set to 0, not the actual amount of tokens minted on the original chain. Therefore, if the balance of the original chain is initialized, the `ITSHub.update_token_balance` will fail due to underflow, making it impossible to send tokens from the original chain to other chains or limiting the amount that can be bridged.

You can initialize the ITSHub balance of the source chain because the `destinationChain` parameter in `InterchainTokenFactory.deployRemoteInterchainToken` does not be checked if it is the source chain of the token. The same issue exists when directly calling `InterchainTokenService.deployInterchainToken` to deploy tokens. This allows token deployment requests from remote chains to the original chain with the same `tokenId`.

While the token with the `tokenId` already exists on the original chain, it's possible to approve the GMP to the original chain, but the transaction will be failed when executed. However, the ITSHub balance initialization occurs during the process of transmitting the GMP to the destination chain, so it doesn't matter if the transaction fails on the original chain. Moreover, the initialized balance is not deleted even if the GMP execution fails.

The same issue occurs when deploying a canonical interchain token through `InterchainTokenFactory.deployRemoteCanonicalInterchainToken`, and it has the most critical severity. The `tokenId` of the canonical token is determined by the address of the original token, and the caller's address does not affect it. Therefore, anyone can call `InterchainTokenFactory.deployRemoteCanonicalInterchainToken` to deploy a specific canonical interchain token. This means anyone can prevent a specific canonical token from being bridged out from the original chain. Since a canonical token can only be registered once, this token can no longer be used normally with the Axelar bridge.

Let's look at an example of what happens when you initialize the ITSHub balance of the original chain. Suppose there are chains A, B, and C, where A is the original chain, and B and C are related chains. Here are the ITSHub balances:

- A: None
- B: 100
- C: 50

Now, using the vulnerability, the balance on chain A has been initialized.

- A: 0
- B: 100
- C: 50

Until chain B or C send some tokens to chain A, no more tokens can be go out from chain A. Also, only a maximum of 150 tokens can move between bridges.

This is a PoC. You can run it by adding it to `interchain-token-service/test/InterchainTokenService.js`. It shows that chain A is the original chain, and after remotely deploying a token from A to B, it's possible to request remote deployment from B to A. On chain A, a token with the same `tokenId` is already deployed, so the GMP execution on the chain A will be failed, but the balance of chain A in ITSHub will be initialized to 0.

```
describe('PoC remote deploy to original chain', () => {
    const tokenName = 'Token Name';
    const tokenSymbol = 'TN';
    const tokenDecimals = 13;
    let sourceAddress;

    before(async () => {
        sourceAddress = service.address;
    });

    it('Can request to remote deploy for original chain', async () => {

        const salt = getRandomBytes32();
        const tokenId = await service.interchainTokenId(wallet.address, salt);
        const tokenManagerAddress = await service.tokenManagerAddress(tokenId);
        const minter = '0x';
        const operator = '0x';
        const tokenAddress = await service.interchainTokenAddress(tokenId);
        const params = defaultAbiCoder.encode(['bytes', 'address'], [operator, tokenAddress]);
        let payload = defaultAbiCoder.encode(
            ['uint256', 'bytes32', 'string', 'string', 'uint8', 'bytes', 'bytes'],
            [MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN, tokenId, tokenName, tokenSymbol, tokenDecimals, minter, operator],
        );
        const commandId = await approveContractCall(gateway, sourceChain, sourceAddress, service.address, payload);

        // 1. Receive remote deployment messages and deploy interchain tokens on the destination chain

        await expect(service.execute(commandId, sourceChain, sourceAddress, payload))
            .to.emit(service, 'InterchainTokenDeployed')
            .withArgs(tokenId, tokenAddress, AddressZero, tokenName, tokenSymbol, tokenDecimals)
            .and.to.emit(service, 'TokenManagerDeployed')
            .withArgs(tokenId, tokenManagerAddress, NATIVE_INTERCHAIN_TOKEN, params);
        const tokenManager = await getContractAt('TokenManager', tokenManagerAddress, wallet);
        expect(await tokenManager.tokenAddress()).to.equal(tokenAddress);
        expect(await tokenManager.hasRole(service.address, OPERATOR_ROLE)).to.be.true;

        // 2. Can request a remote deployment to the source(original) chain

        const destChain = sourceChain;

        payload = defaultAbiCoder.encode(
            ['uint256', 'bytes32', 'string', 'string', 'uint8', 'bytes'],
            [MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN, tokenId, tokenName, tokenSymbol, tokenDecimals, minter],
        );

        await expect(
            reportGas(
                service.deployInterchainToken(salt, destChain, tokenName, tokenSymbol, tokenDecimals, minter, gasValue, {
                    value: gasValue,
                }),
                'Send deployInterchainToken to remote chain',
            ),
        )
            .to.emit(service, 'InterchainTokenDeploymentStarted')
            .withArgs(tokenId, tokenName, tokenSymbol, tokenDecimals, minter, destChain)
            .and.to.emit(gasService, 'NativeGasPaidForContractCall')
            .withArgs(service.address, destChain, service.address, keccak256(payload), gasValue, wallet.address)
            .and.to.emit(gateway, 'ContractCall')
            .withArgs(service.address, destChain, service.address, keccak256(payload), payload);

        // 3. ITSHub will initialize the balance of the original chain
    });
});
```

### Recommended Mitigation Steps

1. In `InterchainTokenFactory.deployRemoteInterchainToken`, check if `destinationChain` is the same as `originalChainName` to prevent remote deployment requests to the original chain.

    ```diff
    function deployRemoteInterchainToken(
        string calldata originalChainName,
        bytes32 salt,
        address minter,
        string memory destinationChain,
        uint256 gasValue
    ) external payable returns (bytes32 tokenId) {
        string memory tokenName;
        string memory tokenSymbol;
        uint8 tokenDecimals;
        bytes memory minter_ = new bytes(0);

        {
            bytes32 chainNameHash_;
            if (bytes(originalChainName).length == 0) {
                chainNameHash_ = chainNameHash;
            } else {
                chainNameHash_ = keccak256(bytes(originalChainName));
            }
    +       require(chainNameHash_ != keccak256(bytes(destinationChain)), "Cannot remote deploy on original chain");

            address sender = msg.sender;
            salt = interchainTokenSalt(chainNameHash_, sender, salt);
            tokenId = interchainTokenService.interchainTokenId(TOKEN_FACTORY_DEPLOYER, salt);

            IInterchainToken token = IInterchainToken(interchainTokenService.interchainTokenAddress(tokenId));

            tokenName = token.name();
            tokenSymbol = token.symbol();
            tokenDecimals = token.decimals();

            if (minter != address(0)) {
                if (!token.isMinter(minter)) revert NotMinter(minter);

                minter_ = minter.toBytes();
            }
        }

        tokenId = _deployInterchainToken(salt, destinationChain, tokenName, tokenSymbol, tokenDecimals, minter_, gasValue);
    }
    ```

2. Check `originalChainName` and `destinationChain` in `InterchainTokenFactory.deployRemoteCanonicalInterchainToken` to ensure that a remote deploy cannot be requested to the original chain.

3. When deploying by `InterchainTokenService.deployInterchainToken` directly, it's not possible to check if the original chain and destination chain are the same. Store information about the original chain for each `tokenId` in ITSHub, and ensure that the balance of the original chain is not initialized.

### Assessed type

Invalid Validation

**[milapsheth (Axelar) confirmed and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8#issuecomment-2334767884):**
 > The report is valid. We consider this a Medium severity issue, however, since assets can't be stolen. It's a DOS issue that prevents canonical tokens from being transferred from the origin chain to other chains. ITS hub can be upgraded easily to handle the scenario where `source_chain == destination_chain` and fix the balance for the source chain, so the impact is low.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8#issuecomment-2362299816):**
 > The Warden has identified a mechanism via which bridging of canonical tokens can be permanently DoSd.
> 
> Upgrades of contract logic are not considered appropriate mitigations for vulnerabilities such as the one described (as we could effectively resolve any and all vulnerabilities identified via upgrades), so I believe that a high-risk severity rating is appropriate for this submission.

**[milapsheth (Axelar) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8#issuecomment-2388292342):**
 > @0xsomeone - In the case of a bug that allows stealing user funds, an upgrade could be too late if the issue is already exploited. Whereas if the DoS issue reported here is triggered, an upgrade can fix the issue without loss of funds. Furthermore, ITS Hub is designed to be upgradable (a non upgradable contract would have made this issue more severe). For this reason, we consider this to be a Medium severity issue since the impact is much lower than a compromise of user funds.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/8#issuecomment-2396605748):**
 > @milapsheth - While from a practical perspective you might consider this to be a medium-severity issue, C4 guidelines are clear that contract upgrades cannot be utilized to mitigate the severity of a vulnerability (i.e. we consider this DoS irrecoverable). As such, this vulnerability's severity will remain from a C4 audit perspective.

***
 
# Medium Risk Findings (2)
## [[M-01]  Axelar cross chain token transfers balance tracking logic is completely broken for rebasing tokens and the transfers of these type of tokens can be exploited](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/117)
*Submitted by [Bauchibred](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/117), also found by [mxuse](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/133), [trachev](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/126), [grearlake](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/121), [ayden](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/120), [ZanyBonzy](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/111), [gjaldon](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/42), and [jasonxiale](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/104)*

> NB: This report is a 2 in 1, first sub section shows how the transfers would be exploited when there is a rebase *(focusing on the solidity implementation of the Hub)* and the second sub section showcases how the balance tracking logic would be completely broken for rebasing tokens *(focusing on the Rust implementation of the ITS Hub)*.

First, it would be key to note that per the scope of the audit we should count rebasing tokens *(whose balance change outside of transfers)* in scope. See what's been stated in the [readMe](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/README.md#scoping-q--a).

| Question | Answer |
| -------- | -------- |
| ERC20 used by the protocol | Any (all possible ERC20s) |
| [Balance changes outside of transfers](https://github.com/d-xo/weird-erc20?tab=readme-ov-file#balance-modifications-outside-of-transfers-rebasingairdrops) | In scope |

### Sub-section 1

There are different token manager types that take care of the different types of tokens that get integrated to the system, i.e., [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interfaces/ITokenManagerType.sol#L10-L17).

```solidity
    enum TokenManagerType {
        NATIVE_INTERCHAIN_TOKEN, // This type is reserved for interchain tokens deployed by ITS, and can't be used by custom token managers.
        MINT_BURN_FROM, // The token will be minted/burned on transfers. The token needs to give mint permission to the token manager, but burning happens via an approval.
        LOCK_UNLOCK, // The token will be locked/unlocked at the token manager.
        LOCK_UNLOCK_FEE, // The token will be locked/unlocked at the token manager, which will account for any fee-on-transfer behaviour.
        MINT_BURN, // The token will be minted/burned on transfers. The token needs to give mint and burn permission to the token manager.
        GATEWAY // The token will be sent throught the gateway via callContractWithToken
    }
```

Now whereas this logic includes a type for fee-on-transfer tokens, there is no logic for supporting rebasing tokens.

Now from the [readMe](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/README.md#L147-L148), we can see that protocol plans to integrate rebasing tokens. Since these tokens do not charge fees during transfers, the method as to which their integration would be done, would be via `LOCK_UNLOCK`.

However, the problem is that after the initial lock at the token manager, there could be a positive/negative rebase of the token before the unlock which would then mean that the amount of tokens transferred in via `takeToken()` would have changed by the time `giveToken()` is to be called to send out these tokens:

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/TokenHandler.sol#L91-L123

```solidity
    function takeToken(
        bytes32 tokenId,
        bool tokenOnly,
        address from,
        uint256 amount
    ) external payable returns (uint256, string memory symbol) {
        address tokenManager = _create3Address(tokenId);
        (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

        if (tokenOnly && msg.sender != tokenAddress) revert NotToken(msg.sender, tokenAddress);

..snip
        } else if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
            _transferTokenFrom(tokenAddress, from, tokenManager, amount);
..snip


        /// @dev Track the flow amount being sent out as a message
        ITokenManager(tokenManager).addFlowOut(amount);

        return (amount, symbol);
    }
```

<https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/TokenHandler.sol#L177-L180>

```solidity
    function _transferTokenFrom(address tokenAddress, address from, address to, uint256 amount) internal {
        // slither-disable-next-line arbitrary-send-erc20
        IERC20(tokenAddress).safeTransferFrom(from, to, amount);
    }
```

<https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/TokenHandler.sol#L45-L80>

```solidity
    function giveToken(bytes32 tokenId, address to, uint256 amount) external payable returns (uint256, address) {
..snip

        if (tokenManagerType == uint256(TokenManagerType.LOCK_UNLOCK)) {
            _transferTokenFrom(tokenAddress, tokenManager, to, amount);
            return (amount, tokenAddress);
        }
..snip
    }
```

Now this would be problematic when we consider the integration in the `InterchainTokenService`, when processing interchain transfers, since the payload attached to the execution would include the right amount of tokens to be sent:

<https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L733-L739>

```solidity
    function _processInterchainTransferPayload(
        bytes32 commandId,
        address expressExecutor,
        string memory sourceChain,
        bytes memory payload
    ) internal {
        bytes32 tokenId;
        bytes memory sourceAddress;
        address destinationAddress;
        uint256 amount;
        bytes memory data;
        {
            bytes memory destinationAddressBytes;
            (, tokenId, sourceAddress, destinationAddressBytes, amount, data) = abi.decode(
                payload,
                (uint256, bytes32, bytes, bytes, uint256, bytes)
            );
            destinationAddress = destinationAddressBytes.toAddress();
        }

        // Return token to the existing express caller
        if (expressExecutor != address(0)) {
            // slither-disable-next-line unused-return
            _giveToken(tokenId, expressExecutor, amount);

            return;
        }

        address tokenAddress;
        (amount, tokenAddress) = _giveToken(tokenId, destinationAddress, amount);


        ..snip
    }
```

But during the time frame where the transfer gets initiated to the time it gets processed, the `amount` specified on that asset might have changed; which would then cause for either the wrong amount of tokens to be given out or for the attempt at transfer to revert when being attempted to be given out [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L1201-L1211).

```solidity

    function _giveToken(bytes32 tokenId, address to, uint256 amount) internal returns (uint256, address tokenAddress) {
        (bool success, bytes memory data) = tokenHandler.delegatecall(
            abi.encodeWithSelector(ITokenHandler.giveToken.selector, tokenId, to, amount)
        );
        if (!success) revert GiveTokenFailed(data);
        (amount, tokenAddress) = abi.decode(data, (uint256, address));

        return (amount, tokenAddress);
    }
```

### Sub-section 2

When executing a message, there is a need to apply the balance tracking logic, see [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L19-L80).

```rust
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
// ..snip

    match its_hub_message {
        ItsHubMessage::SendToHub {
            destination_chain,
            message: its_message,
        } => {
            apply_balance_tracking(//@audit
                deps.storage,
                source_chain.clone(),
                destination_chain.clone(),
                &its_message,
            )?;

// ..snip
        }
        _ => Err(report!(Error::InvalidPayload)),
    }
}
```

While applying the balance logic, this is [documented](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L86-L92) pattern for `interchainTransfers`.

```markdown
/// # Behavior for different ITS message types
///
/// 1. InterchainTransfer:
/// - Decreases the token balance on the source chain.
/// - Increases the token balance on the destination chain.
/// - If the balance becomes insufficient on the source chain, an error is returned.
///
```

We can confirm this in the code snippets:

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L101-L132

```rust
fn apply_balance_tracking(
    storage: &mut dyn Storage,
    source_chain: ChainName,
    destination_chain: ChainName,
    message: &ItsMessage,
) -> Result<(), Error> {
    match message {
        ItsMessage::InterchainTransfer {
            token_id, amount, ..
        } => {
            // Update the balance on the source chain
            update_token_balance(
                storage,
                token_id.clone(),
                source_chain.clone(),
                *amount,
                false,
            )
            .change_context_lazy(|| Error::BalanceUpdateFailed(source_chain, token_id.clone()))?;

            // Update the balance on the destination chain
            update_token_balance(
                storage,
                token_id.clone(),
                destination_chain.clone(),
                *amount,
                true,
            )
            .change_context_lazy(|| {
                Error::BalanceUpdateFailed(destination_chain, token_id.clone())
            })?
        }

        // ..snip
    }
}
```

Evidently the `update_token_balance()` is being queried and in our case would be to the source chain and we'd have our `is_deposited` bool to be false since we are withdrawing, going to the implementation of `update_token_balance()` we can see [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L166-L197).

```rust
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
                    .checked_sub(amount)//@audit
                    .map_err(|_| Error::MissingConfig)?
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
        Some(_) | None => (),
    }

    Ok(())
}
```

Evidently, there is a query of the last stored tracked balance, and an attempt to withdraw more than was last stored, would fail, due to the revert that occurs in rust's `checked_sub()` implementation:

```rust
    pub fn checked_sub(self, other: Self) -> Result<Self, OverflowError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or_else(|| OverflowError::new(OverflowOperation::Sub, self, other))
    }
```

However, this would be wrong for rebasing tokens, cause throughout the duration the token is existing, the `tracked balance != the real balance` this is because these tokens update their balances outside transfers and in the case where they've been multiple positive rebases. Then, we effectively have funds locked in the source chain, because attempting to withdraw what has been tracked, would always [revert here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L185), so simplistic POC would be:

- Token A is well known and the market is good for it's rebasing logic.
- As such over the next ten months there is `~1%` rebase per month.
- With two months with `~1%` negative rebase.
- After a year we have `~10%` positive rebase cumulatively.
- However, transferring these tokens inter-chain would always revert [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L185), when all other amounts have been transferred, leaving `~10% $` worth of assets untransferable.

### Impact

**Sub-section 1:**

As hinted under Proof of Concept, in the case where a rebasing token is integrated then the amount specified in the payload is not necessarily the amount that needs to end up being sent to the user by the time the interchain attempt gets processed; which is because within the time frame the token might have rebased, positively or negatively:

- If a positive rebase, this then means that the interchain transfers would unfairly leak value from the recipient, since they are to receive more than is specified in the payload.
- Alternatively, if a negative rebase, this then means that the recipient is leaking value from the protocol/other users who are attempting to process interchain transfers on the same token.

Which could even open up a sneaky window for tech savvy users to steal value from protocol. This is because, for example, the LIDO stETH token normally rebases around 12pm, so an attacker can always watch the mempool on the rebase from LIDO around the time and in the case where the rebase is going to skim off or heavily increase the balances they can position themselves to make the most out of the transaction by frontrunning the rebase update with requesting an interchain. By the time this is executed, the balance would have already changed for the asset, effectively tricking the system and stealing value from other users.

**Sub-section 2:**

Asides the hinted cases above, if a token's balance is tracked, then there is also no active method to ensure the right tracking is being done for this token, considering positive and negative rebases would occur. This would then mean that during interchain transfers we can have [reverts](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L185) when we should not, essentially meaning a chunk of the assets are going to be stuck/untransferrable from the source chain.

### Recommended Mitigation Steps

**Sub-section 1:**

Do not support these type of tokens, or integrate a new type and then have a way to check the amount of rebase that has happened since the users specified their transfer request.

```diff
    enum TokenManagerType {
        NATIVE_INTERCHAIN_TOKEN, // This type is reserved for interchain tokens deployed by ITS, and can't be used by custom token managers.
        MINT_BURN_FROM, // The token will be minted/burned on transfers. The token needs to give mint permission to the token manager, but burning happens via an approval.
        LOCK_UNLOCK, // The token will be locked/unlocked at the token manager.
        LOCK_UNLOCK_FEE, // The token will be locked/unlocked at the token manager, which will account for any fee-on-transfer behaviour.
+        LOCK_UNLOCK_REBASE, // The token will be locked/unlocked at the token manager, which will account for any positive/negative rebasing behaviour.
        MINT_BURN, // The token will be minted/burned on transfers. The token needs to give mint and burn permission to the token manager.
        GATEWAY // The token will be sent throught the gateway via callContractWithToken
    }
```

**Sub-section 2:**

Do not track the balances for rebasing tokens and instead have them naturally revert [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L185) if not enough balance is available.

### Assessed type

ERC20

**[milapsheth (Axelar) disputed and commented via duplicate Issue #42](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/42#issuecomment-2337069531):**
> ITS only supports tokens that can adhere to the requirements of the supported token managers. It's known that rebasing tokens are not supported by bridging protocols directly. Their wrapped versions should be used (e.g., `wstETH`). So, this is an out of scope requirement and we don't really consider it an issue. It's also been discussed during prior ITS audits.

**[0xsomeone (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/117#issuecomment-2362292808):**
 > The Warden has outlined that the system is inherently incompatible with rebasing tokens.
> 
> The audit's `README` outlines that tokens with balance changes outside of transfers are in the scope of the audit. Even though it might be obvious that such tokens are not supported by bridges directly, the list of token behaviors in scope needs to align with those intentions.
> 
> I am inclined to retain a medium-risk severity rating for this submission due to outlining that the system is inherently incompatible with rebasing tokens even though it purported that it can support balance changes outside of transfers. I would like to note that this submission is considered valid from a C4 audit perspective rather than a technical perspective.

**[milapsheth (Axelar) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/117#issuecomment-2388014733):**
 > ITS intentionally allows linking tokens with custom logic but it's the user's responsibility to ensure that the token's custom logic is compatible with ITS's token bridging model. ITS aims to be a permissionless and flexible protocol, but this requires users to have a good understanding when using it with non-standard ERC20s. This holds for any custom logic and not just rebasing tokens. A user can use ITS with rebasing tokens by registering it under the `MINT_BURN` token type on all chains with the token giving a mint role to the corresponding ITS token managers. What ITS guarantees is that one invalid token link doesn't affect another correctly setup link, thus isolating any issues to the incorrectly setup link. So we think this is a QA report given the model of ITS.


**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/117#issuecomment-2396607898):**
 > @milapsheth - While the submission might be invalid from a practical perspective, a medium-risk severity rating was awarded due to the submission's validity from a C4 perspective. The audit's `README` explicitly includes balance changes outside of transfers as in-scope and this error in the setup of the C4 audit renders this submission to be valid. 

***

## [[M-02] `TokenBalance` limit could be bypassed by deploying `TokenManager`](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76)
*Submitted by [0x007](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76)*

If a chain is compromised, it can not transfer beyond its balance. However, there's a clever way to increase its balance arbitrarily.

A compromised chain can deploy token manager to a token controlled by the attacker on a different chain (or in the future, deploy ITS with their minter address). The balance on that chain would be untracked and the attacker can bridge an unlimited amount to the compromised chain to increase its balance. This is very severe because the main purpose of the hub and audit is to reduce damage to the wider ecosystem when a chain is compromised.

### Proof of Concept

- There are 3 chains: Ethereum, BNB and WoofChain.
- `TokenA` is an ITS on Ethereum and WoofChain, but not on BNB.
- `TokenA` balance on Ethereum is Untracked cause it is the original.
- `TokenA` balance on WoofChain is 1,000.
- WoofChain is compromised.
- We can't bridge more than the 1,000 balance.

So the goal is to create an untracked balance that we can bridge from. We don't want Ethereum, cause we would have to buy and own the real tokens. So instead:

- Deploy FAKE Token on BNB. We can create `UINT256_MAX` totally owned by us.
- Deploy token manager from WoofChain to BNB with the token address set to the FAKE token.
- `TokenA` balance on BNB is now Untracked.
- Transfer a billion `TokenA` from BNB to WoofChain (FAKE token would be burnt/locked).
- `TokenA` balance on WoofChain is now `1,000,000,1000`.
- Transfer the billion `TokenA` to Ethereum.
- The hub confirms that it is less than the balance.
- Ethereum mints the bridged billion `TokenA`.

In fact, transferring to WoofChain to increase the tracked balance is unnecessary. We could have bridged from BNB to the original chain --Ethereum-- if there's an ITS connection between them. According to the "Publicly Known Issues" section of README, the hub would be updated to not track balance when a minter is specified. This would enable the bug in a different function because the attacker could specify their address as the minter.

Examples of a compromise that could happen include:

- Bad precompiles or revert handling: [Godwoken](https://medium.com/risk-dao/how-i-could-drain-an-entire-blockchain-post-mortem-on-a-bug-in-godwoken-chain-2451f83f72d2), [evmos](https://www.asymmetric.re/blog/evmos-precompile-state-commit-infinite-mint)
- Invalid transactions: [frontier](https://github.com/polkadot-evm/frontier/security/advisories/GHSA-hw4v-5x4h-c3xm)
- Consensus or malicious validator: [NEAR](https://hackenproof.com/blog/for-hackers/near-rewards-1-8-million-to-ethical-hackers-at-hackenproof#h2\_2)
- Compiler bugs: [vyper](https://medium.com/rektify-ai/the-vyper-compiler-saga-unraveling-the-reentrancy-bug-that-shook-defi-86ade6c54265)
- Event spoofing
- Contract compromise: e.g., admin key, take over, bug
- Amplifier/routing architecture compromise: External Gateway, Gateway for X on Axelar, Prover, Verifier, Relayer

### Recommended Mitigation Steps

Token hub should store the original chain of each ITS tokenId and allow token or manager deployment from the original chain only. This would limit the access of remote chains to transfers.

### Assessed type

Access Control

**[milapsheth (Axelar) confirmed and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76#issuecomment-2335033700):**
 > The report is valid, although we consider the severity to be Medium since the issue can't be exploited on it's own and requires a severe chain compromise to occur (since ITS by itself doesn't allow deploying token manager for trustless factory tokens). While ITS hub isn't meant to protect against all possible scenarios, it could handle this case by storing the original chain and restricting deployments from the origin chain as the report suggests. This is the same issue discussed in [#43](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/43) and [#77](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/77), although the exploit here is different.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76#issuecomment-2362279845):**
 > The Warden specifies a potential scenario in which a blockchain compromise could affect a balance greater than the original one that was bridged to it.
> 
> I do not believe that a blockchain compromise is meant to reduce the severity of the vulnerability as the ITS system is meant to integrate with as many chains as possible in a "permissionless" manner. As tokens can be directly affected by the described vulnerability, I believe a high-risk severity rating is appropriate. To note, the root cause is different from #77 and #43 and thus, merits its own submission.

**[milapsheth (Axelar) commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76#issuecomment-2388259103):**
 > @0xsomeone - Our reply [here](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/77#issuecomment-2388178827) is relevant for this report, as well. ITS Hub is meant to limit damage in certain scenarios for chains connected to Axelar that have ITS deployed. But chains added by Axelar governance have to still meet a quality and security standard. Furthermore, ITS Hub explicitly whitelists ITS addresses by chain that it trusts. A compromised chain is inherently risky to all connected chains and apps, so ITS hub doesn't allow arbitrary permissionless connections. So without a concrete exploit that can steal user funds, we consider this report to be a Medium severity issue.

**[0xsomeone (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/76#issuecomment-2396605567):**
 > @milapsheth - After reviewing the codebase's documentation, I am inclined to agree that a blockchain compromise is considered a low-likelihood event rendering this submission to be of medium severity.

***

# Low Risk and Non-Critical Issues

For this audit, 25 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/140) by **Bauchibred** received the top score from the judge.

*The following wardens also submitted reports: [Sparrow](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/136), [ZanyBonzy](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/143), [Agontuk](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/149), [K42](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/138), [kirill\_taran](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/135), [MrPotatoMagic](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/134), [bronze\_pickaxe](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/148), [trachev](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/147), [solosync6](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/146), [debo](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/145), [Sisi](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/144), [PolarizedLight](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/142), [0xStalin](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/141), [jasonxiale](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/139), [hunter\_w3b](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/137), [Trooper](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/85), [mxuse](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/79), [ayden](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/62), [fibonacci](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/59), [Bob](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/49), [gjaldon](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/46), [klau5](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/33), [KupiaSec](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/32), and [WenResults](https://github.com/code-423n4/2024-08-axelar-network-findings/issues/18).*

## [01] Approving the interchain service for some supported tokens would never work

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/token-manager/TokenManager.sol#L172-L183

```solidity

    function approveService() external onlyService {
        IERC20(this.tokenAddress()).safeCall(abi.encodeWithSelector(IERC20.approve.selector, interchainTokenService, UINT256_MAX));
    }
```

This function is used to renew approval to the service if need be. Now there is a hardcoded `UINT256_MAX` when trying to give out these approvals, but from the scope for the audit [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/README.md#L156-L157):

```markdown
| Revert on large approvals and/or transfers | In scope |
```

This would then mean that these tokens would not be able to be approved to the `Service`, considering the attempt at approving them always reverts [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/token-manager/TokenManager.sol#L181).

### Impact

Broken functionality for some supported tokens.

### Recommended Mitigation Steps

Consider outrightly not supporting these tokens.

## [02] `chain_bytes` is erroneously allowed to be zero length after splitting

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L67-L83

```rust
impl KeyDeserialize for TokenChainPair {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        if value.len() < 32 {
            return Err(StdError::generic_err("Invalid key length"));
        }
        let (token_id_bytes, chain_bytes) = value.split_at(32); //@audit
        let token_id = TokenId::new(
            token_id_bytes
                .try_into()
                .map_err(|_| StdError::generic_err("Invalid TokenId"))?,
        );
        let chain = ChainName::from_vec(chain_bytes.to_vec())?;

        Ok(TokenChainPair { token_id, chain })
    }
}
```

This is the implementation of `KeyDeserialize` trait for `TokenChainPair`. Note that from the below we can see how `TokenId` is always going to be of length 32, otherwise setting it up to [revert](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/primitives.rs#L44-L45):

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/primitives.rs#L43-L52

```rust
impl KeyDeserialize for TokenId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        if value.len() != 32 {
            return Err(StdError::generic_err("Invalid TokenId length"));//@audit
        }
        Ok(TokenId::new(
            value
                .try_into()
                .map_err(|_| StdError::generic_err("Invalid TokenId"))?,
        ))
    }
}
```

Which is why in the [first snippet](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L67-L83) attached, the value of the `TokenChainPair` is then split [via `value.split_at()` with a `mid` value of 32](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L74) and here is the implementation of the queried `split_at`:

```rust
pub const fn split_at(&self, mid: usize) -> (&[T], &[T]) {
    match self.split_at_checked(mid) {
        Some(pair) => pair,
        None => panic!("mid > len"),
    }
}
```

The problem here is the fact that the [`value.len` is allowed to be exactly equal to 32](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L69-L85), since the [check](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L71) is not inclusive. This would be problematic because even though the splitting does not _panic_ (since `mid = len`), this would then cause the deserialization process to be flawed. We would have a 32-length `token_id_bytes` as expected, but for the `chain_bytes`, we would instead get a zero-length byte slice.

### Impact

Allowing `chain_bytes` to be zero length can lead to issues during deserialization, since this would lead to invalid inputs and essentially a production of an invalid `ChainName`.

### Recommended Mitigation Steps

Make the length check inclusive to ensure we have a valid input for `ChainName` by reverting early if we do not.

```diff
impl KeyDeserialize for TokenChainPair {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
-        if value.len() < 32 {
+        if value.len() <= 32 {
            return Err(StdError::generic_err("Invalid key length"));
        }
        let (token_id_bytes, chain_bytes) = value.split_at(32); //@audit
        let token_id = TokenId::new(
            token_id_bytes
                .try_into()
                .map_err(|_| StdError::generic_err("Invalid TokenId"))?,
        );
        let chain = ChainName::from_vec(chain_bytes.to_vec())?;

        Ok(TokenChainPair { token_id, chain })
    }
}
```

Based on your request, I'll rewrite the report in the specified format, adjusting the content to reflect a more appropriate assessment of the situation.

## [03] Protocol unconsciously limits the amount of token manager types it can have to a small value which could be problematic when Axelar heavily scales

First from the [readMe](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/README.md#L128-L134) this has been stated: 

> **Scoping Q &amp; A**
> **General questions**
> 
> | Question                   | Answer                    |
> | -------------------------- | ------------------------- |
> | ERC20 used by the protocol | Any (all possible ERC20s) |

From the above we can see that protocol intends to integrate with any type of erc20 out there, going to [this section of the docs](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/README.md#erc20-token-behaviors-in-scope) too, we can see how this list is quite long.

Now take a look at the implementation of [`TokenManagerType`](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/primitives.rs#L57-L66):

```rust
pub enum TokenManagerType {
    NativeInterchainToken,
    MintBurnFrom,
    LockUnlock,
    LockUnlockFee,
    MintBurn,
    Gateway,
}
```

This is used to specify the different possible integrations we can have token wise and is then used during transfers or minting to know the specific nature of the token in order to correctly integrate it.

However, the problem is the fact that when converting in `abi.rs` for ABI decoding, the below is being implemented:

```rust
    pub fn abi_decode(payload: &[u8]) -> Result<Self, Report<Error>> {
        // ..snip
let token_manager_type = u8::try_from(decoded.tokenManagerType)//@audit
    .change_context(Error::InvalidTokenManagerType)?
    .then(TokenManagerType::from_repr)
    .ok_or_else(|| Report::new(Error::InvalidTokenManagerType))?;
        // ..snip
    }
```

This current implementation, however, would mean that a `tokenManagerType` of `> 255` would never be supported considering trying to convert it into a `uint8` overflows in the `@audit` tagged instance, which essentially limits the protocol to a maximum of 255 different token manager types.

### Impact

Borderline low/medium, this is going to completely affect the functionality of types above 255. However, the likelihood of this is quite low, but per the docs in this report and from the protocol they plan to integrate a long list of tokens with different features which increases the likelihood of having a lot of token manager types.

### Recommended Mitigation Steps

Apply these changes:

```diff
    pub fn abi_decode(payload: &[u8]) -> Result<Self, Report<Error>> {
        // ..snip
- let token_manager_type = u8::try_from(decoded.tokenManagerType)
+ let token_manager_type = u32::try_from(decoded.tokenManagerType)
    .change_context(Error::InvalidTokenManagerType)?
    .then(TokenManagerType::from_repr)
    .ok_or_else(|| Report::new(Error::InvalidTokenManagerType))?;
        // ..snip
    }
```

Alternatively, if it's certain that the protocol will never need more than 255 token manager types, explicitly document this limitation in the code and consider adding a runtime check to ensure the `tokenManagerType` value never exceeds 255:

```rust
if decoded.tokenManagerType > U256::from(u8::MAX) {
    return Err(Report::new(Error::InvalidTokenManagerType));
}
let token_manager_type = u8::try_from(decoded.tokenManagerType)
    .expect("Value checked to be within u8 range")
    .then(TokenManagerType::from_repr)
    .ok_or_else(|| Report::new(Error::InvalidTokenManagerType))?;
```

## [04] Interchain token servicing lacks any cancellation/deadlining logic

When a transfer is to be made interchain. The current logic is simple to follow:

- User specifies their transfer to the destination chain from the source chain.
- On the destination chain, the transfer gets processed to the destination address.

For some reason the transfer on the receiving chain might fail, this can be from little issues like gas fees, for e.g.

- An interchain transfer gets requested.
- The amount user pays for gas is not enough to process the transaction, so user is only allowed to retry the messages by specifying a higher amount of gas.

This logic would be flawed in some cases, however. Assume the user is trying to transfer `$30` worth of tokens from Arbitrum to Ethereum to pay for whatever. They specify the destination chain and per their calculation the fee to process the tx on Eth is `$15`. They pay less than `$1` on Arb, gas fees are quite cheap.

After sending their request, the gas fees on ETH hikes up by `~30%`, so their first attempt fails, and now they would need to attach `$20` more for their tx. However with this, the user would rather just cancel on Arb pay another `< $1` fee and have access to their `$30 `worth of tokens, but this isn't possible since the current interchaining logic lacks any cancellation approach.

### Impact

QA, since this can be argued to be a design choice by sponsors; however, integrating a cancellation/deadlining logic would allow the best compatibility for users.

Another window for the deadlining could be attributed to the popular lack of deadline for swaps, this is even if slippage is provided, cause in our case here, assume a user made an assumption to process an interchain transfer of a stablecoin and within the timeframe stablecoin on the destination chain heavily depegs, the user still has no option than to just have his tokens locked on the source chain.

### Recommended Mitigation Steps

Introduce a cancellation/deadlining logic.

## [05] Consider allowing contracts/wallets to be part of signers

Currently, signers can be rotated to a new set via [AxelarAmplifierGateway.sol#L96-L107](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L96-L107).

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

But when rotating the signers internally, `ECDSA` is used to verify the signatures [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/governance/BaseWeightedMultisig.sol#L208-L209).

```solidity
        for (uint256 i; i < signaturesLength; ++i) {
            address recoveredSigner = ECDSA.recover(messageHash, signatures[i]);
```

However, the problem is that some users would not be able to access this functionality as valid signatures from them wouldn't work since they can't work with EIP 712.

According to [EIP1271: Standard Signature Validation Method for Contracts](https://eips.ethereum.org/EIPS/eip-1271):

> Externally Owned Accounts (EOA) can sign messages with their associated private keys, but currently contracts cannot. We propose a standard way for any contracts to verify whether a signature on a behalf of a given contract is valid. This is possible via the implementation of a `isValidSignature(hash, signature)` function on the signing contract, which can be called to validate a signature.

So while recovering a valid message signed by these set of users , the return value will be the `bytes4(0)` for any vote signed by a contract (e.g., Multisig) because contracts that sign messages sticking to the EIP1271 standard use the `EIP1271_MAGIC_VALUE` as the successful return for a properly recovered signature. A sample of this is shown within the [EIP1271](https://eips.ethereum.org/EIPS/eip-1271) and also within [CompatibilityFallbackHandler by GnosisSafe](https://github.com/safe-global/safe-smart-account/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/handler/CompatibilityFallbackHandler.sol#L66).

As a result of this scenario, these set of signers would not be able to be integrated since the attempt always fails [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/libs/ECDSA.sol#L61-L65).

```solidity

        signer = ecrecover(hash, v, r, s);

        // If the signature is valid (and not malleable), return the signer address
        if (signer == address(0)) revert InvalidSignature();
```

### Impact

Some intended signers using notable wallet providers would not be addable.

### Recommendations

Consider adding contract signature support by implementing a recovery via the suggested `isValidSignature() `function of the `EIP1271` and comparing the recovered value against the `MAGIC_VALUE`.

## [06] Some tokens can't get deployed on the ITS hub due to current way of querying the metadata

First note that per the scope of the audit any and all possible ERC20s are to be considered, i.e.:

| Question                   | Answer                    |
| -------------------------- | ------------------------- |
| ERC20 used by the protocol | Any (all possible ERC20s) |

> With the only exceptions being high/low decimals.

Now when there is a need to deploy an interchain token, the ERC20 identification data for the token are inquired and stored, for e.g.:

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenFactory.sol#L171-L210

```solidity

    function deployRemoteInterchainToken(
        string calldata originalChainName,
        bytes32 salt,
        address minter,
        string memory destinationChain,
        uint256 gasValue
    ) external payable returns (bytes32 tokenId) {
        string memory tokenName;
        string memory tokenSymbol;
        uint8 tokenDecimals;
        bytes memory minter_ = new bytes(0);

        {
            bytes32 chainNameHash_;
            if (bytes(originalChainName).length == 0) {
                chainNameHash_ = chainNameHash;
            } else {
                chainNameHash_ = keccak256(bytes(originalChainName));
            }

            address sender = msg.sender;
            salt = interchainTokenSalt(chainNameHash_, sender, salt);
            tokenId = interchainTokenService.interchainTokenId(TOKEN_FACTORY_DEPLOYER, salt);

            IInterchainToken token = IInterchainToken(interchainTokenService.interchainTokenAddress(tokenId));

            tokenName = token.name();
            tokenSymbol = token.symbol();
            tokenDecimals = token.decimals();

            if (minter != address(0)) {
                if (!token.isMinter(minter)) revert NotMinter(minter);

                minter_ = minter.toBytes();
            }
        }

        tokenId = _deployInterchainToken(salt, destinationChain, tokenName, tokenSymbol, tokenDecimals, minter_, gasValue);
    }
```

This function is used to deploy a remote interchain token on a specified destination chain. However, the problem is that this function [assumes all ERC20 names are stored as _strings_ on chain](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenFactory.sol#L179); this is wrong and would then cause for the attempt at deploying these tokens remotely to always fail for tokens that have non-string metadata.

### Coded POC

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

// Mock MKR token with bytes32 name and symbol
contract MKR {
    bytes32 public constant name = "Maker";
    bytes32 public constant symbol = "MKR";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 _totalSupply) {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
    }

    // Other ERC20 functions omitted for brevity
}

// Interface representing how the original code expects ERC20 tokens to behave
interface IERC20WithStringMetadata {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

// Simplified InterchainTokenFactory to demonstrate the bug
contract SimplifiedInterchainTokenFactory {
    function deployRemoteInterchainToken(address tokenAddress) external view returns (string memory, string memory, uint8) {
        // This function attempts to read name and symbol as strings, which will fail for MKR
        IERC20WithStringMetadata token = IERC20WithStringMetadata(tokenAddress);
        string memory tokenName = token.name();
        string memory tokenSymbol = token.symbol();
        uint8 tokenDecimals = token.decimals();

        return (tokenName, tokenSymbol, tokenDecimals);
    }
}

contract InterchainTokenFactoryTest is Test {
    MKR public token;
    SimplifiedInterchainTokenFactory public factory;

    function setUp() public {
        token = new MKR(1000000 * 10**18);
        factory = new SimplifiedInterchainTokenFactory();
    }

    function testDeployRemoteInterchainTokenFails() public {
        vm.expectRevert();
        factory.deployRemoteInterchainToken(address(token));
    }
}
```

### Steps to reproduce

- Create a standalone foundry project and name a test file: `InterchainTokenFactoryTest.t.sol`.
- Run the test with `forge test --match-test testDeployRemoteInterchainTokenFails -vv`.

### Impact

Tokens with non-string metadata can't get deployed on the ITS.

### Recommended Mitigation Steps

Check the metadata data type of added tokens.

## [07] A user would be able to execute an interchain transfer for free

Whenever there is a need to process interchain transfers the `_transmitInterchainTransfer()` gets called, now the amount of gas that's to be payed to process this transfer is also attached with this query; for example, [see this instance in `InterchainTokenService#interchainTransfer()`](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L454-L478).

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L1148-L1185

```solidity
    function _transmitInterchainTransfer(
        bytes32 tokenId,
        address sourceAddress,
        string calldata destinationChain,
        bytes memory destinationAddress,
        uint256 amount,
        IGatewayCaller.MetadataVersion metadataVersion,
        bytes memory data,
        string memory symbol,
        uint256 gasValue
    ) internal {
        if (amount == 0) revert ZeroAmount();

        // slither-disable-next-line reentrancy-events
        emit InterchainTransfer(
            tokenId,
            sourceAddress,
            destinationChain,
            destinationAddress,
            amount,
            data.length == 0 ? bytes32(0) : keccak256(data)
        );

        bytes memory payload = abi.encode(
            MESSAGE_TYPE_INTERCHAIN_TRANSFER,
            tokenId,
            sourceAddress.toBytes(),
            destinationAddress,
            amount,
            data
        );
        if (bytes(symbol).length > 0) {
            _callContractWithToken(destinationChain, payload, symbol, amount, metadataVersion, gasValue);
        } else {
            _callContract(destinationChain, payload, metadataVersion, gasValue);
        }
    }
```

As hinted earlier on, this function transmits the `callContract`... prefixed functionalities for the given `tokenId`. Per the [documentation](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L277-L278), it can be deduced that whenever `gasValue` is attached, it should be at least `msg.value` and then the remainder would be refunded to the specified `tx.origin`.

However, the problem is that no where is this enforced; which then allows anyone to pass any value as their `gasValue` when querying, for example, [`InterchainTokenService#interchainTransfer()`](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L454-L478) while actually attaching way less than that as their `msg.value`.

### Impact

Borderline low/medium. Per information from the sponsors the contract is never expected to hold native funds in it, but this in short causes a leak of value, since users can get their interchain transfers processed for relatively free.

### Recommended Mitigation Steps

Consider explicitly checking in the outermost query that needs `gasValue` that indeed the msg.value provided is at least up to this value.

## [08] `execute.rs` still uses a placeholder for the tx hash

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs#L14-L15

```rust
const PLACEHOLDER_TX_HASH: [u8; 32] = [0u8; 32];
```

A placeholder is being uses to substitute the tx hash, [since cosmwasm doesn't provide it](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs#L14), now there is an [open todo to get this from core](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs#L14). However, this has not been sorted in production code.

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs#L28-L32

```rust
    let message_id = HexTxHashAndEventIndex {
        tx_hash: PLACEHOLDER_TX_HASH,
        event_index: counter,
    }
    .to_string();
```

### Recommended Mitigation Steps

Get the actual tx hash from core.

## [09] An attacker can potentially brick interchain transfers for as little as spending 1 wei in each epoch

First note that from the readMe, any type of ERC20 token is intended to be integrated.

Now protocol integrates a flow limiting logic and in order for [interchain transfers](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L632) to be processed, there is a need to check the amount being received/sent against the flow limit, for e.g., consider `giveToken()` that gets called [whenever there is a need to process an interchain transfer](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L741-L751). This function adds in the flown amount before finalizing the transfer, and when adding the in-flown amount, there is a [check that reverts](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/utils/FlowLimit.sol#L103-L104) when the limit is passed.


https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/utils/FlowLimit.sol#L94-L110

```solidity
    function _addFlow(uint256 flowLimit_, uint256 slotToAdd, uint256 slotToCompare, uint256 flowAmount) internal {
        uint256 flowToAdd;
        uint256 flowToCompare;

        assembly {
            flowToAdd := sload(slotToAdd)
            flowToCompare := sload(slotToCompare)
        }

        if (flowToAdd + flowAmount > flowToCompare + flowLimit_)
            revert FlowLimitExceeded((flowToCompare + flowLimit_), flowToAdd + flowAmount, address(this));
        if (flowAmount > flowLimit_) revert FlowLimitExceeded(flowLimit_, flowAmount, address(this));

        assembly {
            sstore(slotToAdd, add(flowToAdd, flowAmount))
        }
    }
```

Now from [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interfaces/ITokenManagerType.sol#L10-L17), we can see the different supported token manager types.

```solidity
    enum TokenManagerType {
        NATIVE_INTERCHAIN_TOKEN, // This type is reserved for interchain tokens deployed by ITS, and can't be used by custom token managers.
        MINT_BURN_FROM, // The token will be minted/burned on transfers. The token needs to give mint permission to the token manager, but burning happens via an approval.
        LOCK_UNLOCK, // The token will be locked/unlocked at the token manager.
        LOCK_UNLOCK_FEE, // The token will be locked/unlocked at the token manager, which will account for any fee-on-transfer behaviour.
        MINT_BURN, // The token will be minted/burned on transfers. The token needs to give mint and burn permission to the token manager.
        GATEWAY // The token will be sent throught the gateway via callContractWithToken
    }
```

The issue is the fact that the [token balance differences logic is only employed for the classic Fee on transfer tokens in the Token Handler](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/TokenHandler.sol#L187-L204). This then allows for tokens like cUSDCv3's integration to be broken; this is because whereas this token is not a FOT token, it also includes a tweak in it's transfer logic.

Now with [`cUSDCv3`](https://etherscan.io/address/0xbfc4feec175996c08c8f3a0469793a7979526065#code), its implementation of transferFrom [calls the internal `transferInternal` function here](https://etherscan.io/address/0xbfc4feec175996c08c8f3a0469793a7979526065#code) and if we attach `type(uint256).max` it only transfers the amount of tokens the user owns.

```solidity
    function transferInternal(address operator, address src, address dst, address asset, uint amount) internal {
        if (isTransferPaused()) revert Paused();
        if (!hasPermission(src, operator)) revert Unauthorized();
        if (src == dst) revert NoSelfTransfer();

        if (asset == baseToken) {
            if (amount == type(uint256).max) {
                amount = balanceOf(src);
            }
            return transferBase(src, dst, amount);
        } else {
            return transferCollateral(src, dst, asset, safe128(amount));
        }
    }
```

This then means that if the flow limit for an epoch gets set, any malicious intended user can take the following steps 4 times a day, _An epoch lasts 6 hours_, and ensure transfers are permanently blocked:

- Attacker owns two addresses.
- They send in 1 wei to the attacking address at the end of each epoch.
- At the start of an epoch they call an interchain transfer with `type(uint256).max` which ends up flawing the flow limits since they real value sent in would be just 1 wei.

### Impact

QA, this is because a trusted admin should set this token as an FOT token; however, this might be missed as it only includes this logic when being transferred with an amount of `type(uint256).max`.

### Recommended Mitigation Steps

Consider not supporting this type of token or just check balances for each token manager type, since upgraded tokens are supported.

## [10] Migration does nothing in `interchain-token-service/src/contract.rs`

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs#L15-L17

```rust
const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
```

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract.rs#L42-L50

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // @audit
    Ok(Response::default())
}
```

This function is used to migrate; however, its implementation is incomplete cause it doesn't set neither the contract's version or name.

The correct implementation can be seen here in ITS Hub's gateway [implementation](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs#L51-L62).

```rust
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
```

Also from [CosmWasm's docs on migration](https://docs.burnt.com/xion/develop/cosmwasm-resources/contract-semantics/migration), we can see how it's expected to call `set_contract_version()` during migration.

### Impact

This absence of proper version/name management could make it impossible to implement version-specific migration logic or prevent incompatible migrations, since we are not updating and checking the contract version during migration.

Since [`set_contract_version` is called in the `instantiate` function](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract.rs#L59-L60), it is not being atomically executed during migration, leaving the version information outdated after each migration.

### Recommended Mitigation Steps

Implement proper version management in the `migrate` function.

Pseudo fix:

```rust

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let version = cw2::get_contract_version(deps.storage)?;
    if version.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidContract);
    }

    // Perform version-specific migration logic here if needed

    // Update to the new version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("action", "migrate"))
}
```

## [11] Setters: `migrate()` does not have an equality checker or something similar

Take a look at the current implementation of the contract's `migrate` function [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs#L87-L88).

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}
```

The `migrate` function sets the contract version using `cw2::set_contract_version`, but it does not check the current version of the contract before performing the migration. This would be wrong if the version it's being set to is already the current version or can even lead to issues if the migration is attempted from an incompatible or newer version of the contract.

### Impact

Without checking the current version of the contract using `get_contract_version`, there is a risk of setting the contract to the same version or even worse, attempting to migrate from a newer version to an older version; which is generally not advisable and can cause loss of functionality or data.

### Recommended Mitigation Steps

Use the `get_contract_version` function to retrieve the current version of the contract before performing the migration. Then ensure that the migration is only performed if the current version is older than the new version being deployed.

Pseudo fix:

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    use semver::Version;

    // Retrieve the current contract version
    let storage_version = cw2::get_contract_version(deps.storage)?;
    let current_version: Version = storage_version.version.parse()?;
    let new_version: Version = CONTRACT_VERSION.parse()?;

    // Ensure we are migrating from an older version
    if current_version >= new_version {
        return Err(axelar_wasm_std::error::ContractError::Std(
            cosmwasm_std::StdError::generic_err("Cannot migrate from a newer or same contract version"),
        ));
    }

    // Set the new contract version
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}
```

## [12] Current implementation does not allow for encoding/decoding very large data

The `abi.rs` includes an execution to help encode/decode data, this can be seen here: [abi.rs#L77-L178](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/abi.rs#L77-L178), via `abi_encode()` & `abi_decode()`. However, this fails for quite large data.

### Coded POC

Attach the test below:

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/abi.rs#L554-L570

```rust
    fn encode_decode_large_data_fails() {
        let large_data = vec![0u8; 81200 * 812o0]; // large data
        let original = ItsHubMessage::SendToHub {
            destination_chain: ChainName::from_str("large-data-chain").unwrap(),
            message: ItsMessage::InterchainTransfer {
                token_id: [0u8; 32].into(),
                source_address: HexBinary::from_hex("1234").unwrap(),
                destination_address: HexBinary::from_hex("5678").unwrap(),
                amount: Uint256::from(1u128),
                data: HexBinary::from(large_data),
            },
        };

        let encoded = original.clone().abi_encode();
        let decoded = ItsHubMessage::abi_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
```

We see how it fails with a `SIGKILL` revert.

### Impact

QA, since the instances where payload is being used have a very low likelihood of including a data size this large.

## [13] Potential DoS in message routing logic due to a single invalid message

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/gateway/src/contract/execute.rs#L32-L48

```rust
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified)?;

    for msg in msgs.iter() {
        state::save_outgoing_message(store, &msg.cc_id, msg)
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::Routing { msg }.into()),
    ))
}
```

The current implementation of `route_outgoing_messages` can lead to a Denial of Service (DoS) scenario. If any single message in the `verified` vector fails to save (due to `Error::SaveOutgoingMessage`), the entire function will return an error, preventing all other valid messages from being processed, which blocks the routing of numerous valid messages due to a single problematic entry.

### Impact

QA, per the information [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/gateway/src/contract/execute.rs#L31). The messages should be verified, however, this causes for any other valid message to not be routed.

### Recommended Mitigation Steps

1. Modify the function to continue processing messages even if some fail:

```rust
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified)?;
    let mut successful_msgs = Vec::new();
    let mut failed_msgs = Vec::new();

    for msg in msgs.iter() {
        match state::save_outgoing_message(store, &msg.cc_id, msg) {
            Ok(_) => successful_msgs.push(msg.clone()),
            Err(e) => failed_msgs.push((msg.cc_id.clone(), e)),
        }
    }

    let response = Response::new()
        .add_events(successful_msgs.iter().map(|msg| GatewayEvent::Routing { msg: msg.clone() }.into()))
        .add_attribute("successful_messages", successful_msgs.len().to_string())
        .add_attribute("failed_messages", failed_msgs.len().to_string());

    Ok(response)
}
```

2. Implement a logging mechanism for failed messages to track and potentially address issues:

```rust
// Add this to your logging or monitoring system
for (cc_id, error) in failed_msgs {
    log::warn!("Failed to save outgoing message {}: {:?}", cc_id, error);
}
```

3. Consider implementing a retry mechanism for failed messages, potentially with a maximum retry count to prevent infinite loops.

4. Update the contract's error handling to provide more granular information about partial successes and failures in message routing.

By implementing these changes, the contract will be more resilient to individual message failures and provide better visibility into the success rate of message routing operations.

## [14] A whale can always DOS interchain transfers when flow limit is set

In order for [interchain transfers](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L632) to be processed, there is a need to check the amount being received/sent against the flow limit, for e.g., consider `giveToken()` that gets called [whenever there is a need to process an interchain transfer](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L741-L751).

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/TokenHandler.sol#L45-L79

```solidity
    function giveToken(bytes32 tokenId, address to, uint256 amount) external payable returns (uint256, address) {
        address tokenManager = _create3Address(tokenId);

        (uint256 tokenManagerType, address tokenAddress) = ITokenManagerProxy(tokenManager).getImplementationTypeAndTokenAddress();

        /// @dev Track the flow amount being received via the message
        ITokenManager(tokenManager).addFlowIn(amount);

// snip

        revert UnsupportedTokenManagerType(tokenManagerType);
    }
```

Now this function adds in the flown amount before finalizing the transfer, now when adding the inflown amount, there is a [check that reverts](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/utils/FlowLimit.sol#L103-L104) when the limit is passed.

> NB: The call route [reaches the reversion](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/utils/FlowLimit.sol#L103-L104) via : `InterchainTokenService#executeWith()/executeWithToken() -> InterchainTokenService#_processInterchainTransferPayload() -> _processInterchainTransferPayload#_giveToken() -> TokenHandler#giveToken() -> TokenManager#addFlowIn() -> TokenManager#_addFlow()`.

This then allows a whale to always DOS the channel and block off deposits for the whole duration, cause immediately the epoch starts, they pass in a payload to transfer flowlimit cross chain and once this gets processed all subsequent transfers would fail cause the flowlimit has been reached.

### Impact

Reoccurring DOS for interchain transfers, and this could be repeated at relatively low cost, since all the attacker pays is the minute gas fees to pass in the request.

### Recommended Mitigation Steps

Consider having a max limit for a particular sender/receiver whenever the flow limit is set, this could be like 10% of the flowlimit set.

## [15] The minimum rotation delay should be enforced

The documentation for the Axelar Amplifier Gateway Integration states:

> To prevent the gateway contract from being lost by successive malicious rotations, a minimum delay is enforced between signer rotations (e.g., 1 day). This allows the decentralized governance to step in to react to any issues (for e.g., upgrade the gateway).

See [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/gateway/INTEGRATION.md). However, the implementation in the BaseWeightedMultisig contract does not enforce this 1-day minimum:

```solidity
uint256 public immutable minimumRotationDelay;

constructor(
    uint256 previousSignersRetention_,
    bytes32 domainSeparator_,
    uint256 minimumRotationDelay_
) {
    previousSignersRetention = previousSignersRetention_;
    domainSeparator = domainSeparator_;
    minimumRotationDelay = minimumRotationDelay_;
}

function _updateRotationTimestamp(bool enforceRotationDelay) internal {
    uint256 lastRotationTimestamp_ = _baseWeightedMultisigStorage().lastRotationTimestamp;
    uint256 currentTimestamp = block.timestamp;

    if (enforceRotationDelay && (currentTimestamp - lastRotationTimestamp_) < minimumRotationDelay) {
        revert InsufficientRotationDelay(
            minimumRotationDelay,
            lastRotationTimestamp_,
            currentTimestamp - lastRotationTimestamp_
        );
    }

    _baseWeightedMultisigStorage().lastRotationTimestamp = currentTimestamp;
}
```

The contract allows setting any value for `minimumRotationDelay`, including values less than 1 day.

### Impact

This discrepancy between the documentation and implementation could lead to:

1. Violation of the security model described in the documentation.
2. Potential vulnerability to rapid signer rotations, which could be exploited in an attack.
3. Insufficient time for decentralized governance to react to malicious activities.
4. Confusion for developers and users expecting a minimum 1-day delay as per the documentation.

QA, since this relies on trusted parties, but since Axelar assumes the risk of signers turning malicious being noteworthy then this should be flagged.

### Recommended Mitigation Steps

Introduce a constant for the minimum allowed rotation delay:

```diff
+ uint256 private constant MINIMUM_ALLOWED_ROTATION_DELAY = 1 days;

constructor(
    uint256 previousSignersRetention_,
    bytes32 domainSeparator_,
    uint256 minimumRotationDelay_
) {
+   require(minimumRotationDelay_ >= MINIMUM_ALLOWED_ROTATION_DELAY, "Rotation delay too low");
    previousSignersRetention = previousSignersRetention_;
    domainSeparator = domainSeparator_;
    minimumRotationDelay = minimumRotationDelay_;
}
```

## [16] `axelarnet-gateway/execute.rs#call_contract()` should include better error handling

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract/execute.rs#L41-L42

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
    // ..snip
    let msg = Message {
        cc_id: cc_id.clone(),
source_address: Address::try_from(sender.clone().into_string())
    .expect("failed to convert sender address"),
    // ..snip
    }
    ..
}
```

The current implementation uses `expect()` for the address conversion, which will cause a panic if the conversion fails, which naturally is a worse option than better error handling; in rust projects, panicking in some cases leads to the halt of a chain.

### Recommended Mitigation Steps

Consider replacing the `expect()` call with proper error handling:

```rust
source_address: Address::try_from(sender.clone().into_string())
    .map_err(|e| Error::AddressConversionFailed(e.to_string()))?,
```

A new error variant within an `Error` enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ... other error variants ...
    #[error("Failed to convert sender address: {0}")]
    AddressConversionFailed(String),
}
```

Then update the `call_contract` function signature to propagate this new error:

```rust
pub(crate) fn call_contract(
    // ... other parameters ...
) -> Result<Response, Error> {
    // ... existing code ...
}
```

Alternatively, consider adding input validation for the `sender` address before attempting conversion:

```rust
if !is_valid_address_format(&sender) {
    return Err(Error::InvalidAddressFormat(sender.to_string()));
}
```

## [17] Consider having a `_gap` in storage for upgradable contracts

The [InterchainTokenService.sol](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/InterchainTokenService.sol#L34-L43) contract is upgradable; however, it lacks any `_gap` variable which could lead to a compromise of compatibility when adding new state variables.

```solidity
contract InterchainTokenService is
    Upgradable,
    Operator,
    Pausable,
    Multicall,
    Create3AddressFixed,
    ExpressExecutorTracker,
    InterchainAddressTracker,
    IInterchainTokenService
```

### Recommended Mitigation Steps

Consider having a `_gap` in storage for upgradable contracts.

## [18] Remove redundant checks from `query()`

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs#L133-L145

```rust
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::OutgoingMessages { message_ids } => {
            let msgs = query::outgoing_messages(deps.storage, message_ids.iter())?;
            to_json_binary(&msgs).change_context(Error::SerializeResponse)
        }
    }?
    .then(Ok)
}
```

The use of `.then(Ok)` at the end of the `query` function seems redundant because the function already returns a `Result` type due to the use of the `?` operator in the preceding lines.

### Impact

QA - code improvements, which is because this redundancy does not introduce a functional bug but clutters the code and can lead to confusion about the function's error handling logic. It suggests an unnecessary transformation of the result, which is not required since the function's operations already ensure a `Result` type is returned.

### Recommended Mitigation Steps

The `.then(Ok)` method is unnecessary and can be removed without altering the function's behavior. The function signature ensures a `Result<Binary, axelar_wasm_std::error::ContractError>` return type, and the `?` operator already handles error propagation correctly. So consider simplifying the function by removing `.then(Ok)` to make the code cleaner and more readable.

## [19] Some errors from `contract.rs#L21-L41` are abandoned

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract.rs#L21-L41

```rust
pub enum Error {
    #[error("contract config is missing")]
    ConfigMissing,
    #[error("invalid store access")]
    InvalidStoreAccess,
    #[error("invalid address")]
    InvalidAddress,
    #[error("untrusted source address {0}")]
    UntrustedAddress(Address),
    #[error("failed to execute ITS command")]
    Execute,
    #[error("unauthorized")]
    Unauthorized,
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("untrusted sender")]
    UntrustedSender,
    #[error("failed to update balance on chain {0} for token id {1}")]
    BalanceUpdateFailed(ChainName, TokenId),
}
```

These errors are used to propagate several wrong cases across the [Rust ITS Hub](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service) issue; however, is that not all are being used, leaving the users/devs/integrators lost when there is a case where an error is to be bubbled but protocol fails to do so.

Among the ones not being used, we have:

```rust

    #[error("failed to execute ITS command")]
    Execute,
    #[error("unauthorized")]
    Unauthorized,
    #[error("untrusted sender")]
    UntrustedSender,
```

This can be confirmed by these search commands:

- https://github.com/search?q=repo%3Acode-423n4%2F2024-08-axelar-network+Execute+language%3ARust&type=code
- https://github.com/search?q=repo%3Acode-423n4%2F2024-08-axelar-network+Unauthorized+language%3ARust&type=code
- https://github.com/search?q=repo%3Acode-423n4%2F2024-08-axelar-network+UntrustedSender+language%3ARust&type=code

### Recommended Mitigation Steps

Consider correctly propagating errors if possible, instead of silently failing.

## [20] The rust ITS Hub should correctly relay when there is an insufficient balance while updating the balance on the source chain

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L17-L22

```rust
pub enum Error {
    // ..snip

    InsufficientBalance {
        token_id: TokenId,
        chain: ChainName,
        balance: Uint256,
    },
    // ..snip
```

This error has been attached in the primitives in order to correctly inform when there is insufficient balance for token `token_id` on chain `chain`; however, the issue is that throughout the [Rust ITS Hub](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service) this error never gets used unlike [others listed in the same enum](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L10-L26), this can be confirmed by this [search command](https://github.com/search?q=repo%3Acode-423n4%2F2024-08-axelar-network+InsufficientBalance+language%3ARust&type=code&l=Rust): 

https://github.com/search?q=repo%3Acode-423n4%2F2024-08-axelar-network+InsufficientBalance+language%3ARust&type=code&l=Rust

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L166-L196

```rust
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
                    .map_err(|_| Error::MissingConfig)?
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
        Some(_) | None => (),
    }

    Ok(())
}
```

This function is used to [update the token balances both on the source chain and the destination chain in the time of interchain transfers](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/contract/execute.rs#L88-L92); however, the issue is the fact that the function doesn't error out as intended, this is because in the case where there is an error in the `checked_sub()` instead of returning the correct error, we instead have a missing configuration, instead of the hinted `InsufficientBalance()` earlier.

### Recommended Mitigation Steps

Consider integrating the error in the [Rust ITS Hub](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service), most especially to be used [while updating the token balances on the source chain](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L186).

## [21] Unnecessary `v` value check in `ERC20Permit#permit()`

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interchain-token/ERC20Permit.sol#L71-L92

```solidity
    function permit(address issuer, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert PermitExpired();

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidS();

        if (v != 27 && v != 28) revert InvalidV();

        bytes32 digest = keccak256(
            abi.encodePacked(
                EIP191_PREFIX_FOR_EIP712_STRUCTURED_DATA,
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_SIGNATURE_HASH, issuer, spender, value, nonces[issuer]++, deadline))
            )
        );

        address recoveredAddress = ecrecover(digest, v, r, s);

        if (recoveredAddress != issuer) revert InvalidSignature();

        // _approve will revert if issuer is address(0x0)
        _approve(issuer, spender, value);
    }
```

This function is used to permit a designated spender, now it includes the `uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` check to ensure the signatures are not malleable.

However, the issue is that it also includes a `if (v != 27 && v != 28) revert InvalidV()` check which is redundant. See more info [here](https://twitter.com/alexberegszaszi/status/1534461421454606336?s=20&t=H0Dv3ZT2bicx00hLWJk7Fg).

### Recommended Mitigation Steps

Consider applying these changes:

```diff
    function permit(address issuer, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert PermitExpired();

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidS();

-        if (v != 27 && v != 28) revert InvalidV();

        bytes32 digest = keccak256(
            abi.encodePacked(
                EIP191_PREFIX_FOR_EIP712_STRUCTURED_DATA,
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_SIGNATURE_HASH, issuer, spender, value, nonces[issuer]++, deadline))
            )
        );

        address recoveredAddress = ecrecover(digest, v, r, s);

        if (recoveredAddress != issuer) revert InvalidSignature();

        // _approve will revert if issuer is address(0x0)
        _approve(issuer, spender, value);
    }
```

## [22] Consider a two-way transfer of operators/governance

Multiple instances where this bug case occurs in the protocol's logic:

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/gateway/AxelarAmplifierGateway.sol#L127-L145

```solidity

    function transferOperatorship(address newOperator) external onlyOperatorOrOwner {
        _transferOperatorship(newOperator);
    }

    function _transferOperatorship(address newOperator) internal {
        _axelarAmplifierGatewayStorage().operator = newOperator;

        emit OperatorshipTransferred(newOperator);
    }
```

The operator is quite critical in scope, however, it's only transferred in one step.

### Recommended Mitigation Steps

Consider implementing a proposal/acceptance to avoid accidentally handing it over to the wrong address.

## [23] Consider making `timeSinceRotation()` more useful via using it in `_updateRotationTimestamp()`

Take a look at the `timeSinceRotation` function in the `BaseWeightedMultisig` contract:

```solidity
function timeSinceRotation() external view returns (uint256) {
    return block.timestamp - _baseWeightedMultisigStorage().lastRotationTimestamp;
}
```

This function is not used within the contract. However, its functionality could be utilized in the `_updateRotationTimestamp` function:

```solidity
function _updateRotationTimestamp(bool enforceRotationDelay) internal {
    uint256 lastRotationTimestamp_ = _baseWeightedMultisigStorage().lastRotationTimestamp;
    uint256 currentTimestamp = block.timestamp;
    if (enforceRotationDelay && (currentTimestamp - lastRotationTimestamp_) < minimumRotationDelay) {
        revert InsufficientRotationDelay(
            minimumRotationDelay,
            lastRotationTimestamp_,
            currentTimestamp - lastRotationTimestamp_
        );
    }
    // ...
}
```

The `(currentTimestamp - lastRotationTimestamp_)` calculation in `_updateRotationTimestamp` duplicates the logic in `timeSinceRotation`.

### Impact

QA, this is a code quality issue with no direct security implications. However, it represents a missed opportunity for code reuse and improved readability.

### Recommended Mitigation Steps

To improve code quality and readability, utilize the `timeSinceRotation` function in `_updateRotationTimestamp`:

```solidity
function _updateRotationTimestamp(bool enforceRotationDelay) internal {
    uint256 timeSinceLastRotation = timeSinceRotation();
    if (enforceRotationDelay && timeSinceLastRotation < minimumRotationDelay) {
        revert InsufficientRotationDelay(
            minimumRotationDelay,
            _baseWeightedMultisigStorage().lastRotationTimestamp,
            timeSinceLastRotation
        );
    }
    // ...
}
```

## [24] `outgoing_messages` could be made more efficient

Take a look at [the `outgoing_messages` method in the `Client` struct](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/client.rs#L47-L51):

```rust
pub fn outgoing_messages(&self, message_ids: Vec<CrossChainId>) -> Result<Vec<Message>> {
    self.client
        .query(&QueryMsg::OutgoingMessages { message_ids })
        .change_context_lazy(|| Error::QueryAxelarnetGateway(self.client.address.clone()))
}
```

Evidently, in the case of an error, the method changes the context of the error to `Error::QueryAxelarnetGateway`, but it does not provide detailed information about the original error. This can make it difficult to diagnose the root cause of the error, as the original error information is lost.

### Recommended Mitigation Steps

Ensure that the original error information is preserved and included in the new context to provide more detailed error messages.

Pseudo fix:

```rust
pub fn outgoing_messages(&self, message_ids: Vec<CrossChainId>) -> Result<Vec<Message>> {
    self.client
        .query(&QueryMsg::OutgoingMessages { message_ids })
        .map_err(|e| {
            let new_error = Error::QueryAxelarnetGateway(self.client.address.clone());
            eprintln!("Error querying outgoing messages: {:?}", e);
            e.change_context(new_error)
        })
}
```

## [25] Supportive tests for more coverage in `client.rs`

Attach the tests below to [axelarnet-gateway/src/client.rs](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/contracts/axelarnet-gateway/src/client.rs#L154-L181):

```rust
    fn route_messages_empty() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        let result = client.route_messages(Vec::new());

        assert!(result.is_none(), "Expected None for empty messages vector");
    }
    #[test]
    fn outgoing_messages_no_data() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        // Create CrossChainId instances explicitly
        let message_ids = vec![
            CrossChainId::new("sourcechain", "non-existent-id").unwrap(),
            CrossChainId::new("sourcechain", "another-non-existent-id").unwrap(),
        ];
        let result = client.outgoing_messages(message_ids);

        assert!(
            result.is_err(),
            "Expected error due to non-existent message IDs"
        );
    }
```

Test cases were developed during the audit to test a few bug cases, seems like a good addition to make.

### Impact

QA, more test coverage.

### Recommended Mitigation Steps

Consider adding the test specified.

## [26] Inconsistency with EIP1967

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-gmp-sdk-solidity/contracts/upgradable/BaseProxy.sol#L14-L17

```solidity
    // keccak256('owner')
    bytes32 internal constant _OWNER_SLOT = 0x02016836a56b71f0d02689e69e326f4f4c1b9057164ef592671cf0d37c8040c0;
```

This is one of the instances where the owner is being stored, according to EIP1967. However, it should be `Storage slot 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 (obtained as bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1))`.

### Recommended Mitigation Steps

Consider being consistent with the tested/trusted EIP.

## [27] The invariant of ITS not holding any token to be broken

> NB: This case is more like a _note_ and not a _low/nc_ issue

They do not expect the ITS to hold any tokens; however, this invariant can be broken in a number of ways:

- Rebasing tokens, for example, whereas the likelihood is low after a transfer a token could positively rebase and the transfer out would not match the transfer in so the ITS would be left with these extra tokens.
- Or, a contract deploying, self destructing and having the ITS as recipient.
- Or, a miner setting up the iTS as the address for mining rewards.

### Impact

QA, considering this doesn't necessarily have any impact on the protocol. But if these assets would be considered protocol's after getting into ITS, then a random user could steal them due to the previous assumption that the ITS should have no balance.

### Recommended Mitigation Steps

Consider not directly relying on the fact that on a normal note the ITS should not have any balance and instead have functionalities to contain this.

## [28] Balance tracking could be broken for some supported tokens

The protocol supports tokens with multiple addresses, as stated in the README. When executing messages, balance tracking is initiated for new token deployments on destination chains. However, the current implementation fails to account for tokens with multiple addresses.

The `start_token_balance` function only checks if a token is already registered using a single address:

```rust
match TOKEN_BALANCES.may_load(storage, key.clone())? {
    None => {
        // Initialize balance
    }
    Some(_) => Err(Error::TokenAlreadyRegistered {
        token_id: key.token_id,
        chain: key.chain,
    }),
}
```

This allows different balance tracking logic to be applied for the same token using its multiple addresses, potentially resetting tracked balances.

### Impact

Accurate balance tracking becomes impossible for multi-address tokens, as new balances can be initiated for each address, effectively resetting the tracked balance for the token.

> NB: A somewhat similar logic could be applied to the current `flowlimiting` logic.

### Recommended Mitigation Steps

Consider not supporting tokens with multiple addresses, or implement a mechanism to link all addresses of a token to a single balance tracking entry which seems impossible since some of these tokens are upgradeable.

## [29] Nonce is never used in regards to the weighted signers, allowing for proof/signature replay

The `WeightedSigners` struct includes a `nonce` field, which is typically used to prevent replay attacks. However, upon inspection of the whole, this nonce is never actually checked or updated when validating proofs or signatures.

### Impact

The lack of nonce usage in the validation process potentially allows for replay attacks. An attacker could potentially reuse valid proofs or signatures multiple times, leading to unauthorized actions or double-spending issues.

### Recommended Mitigation Steps

Implement a nonce checking mechanism in the proof/signature validation process. Each time a proof is used, the nonce should be incremented.

## [30] Fix typos

See [here](https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/interchain-token-service/contracts/interfaces/ITokenManagerType.sol#L9-L18).

```solidity
interface ITokenManagerType {
    enum TokenManagerType {
        NATIVE_INTERCHAIN_TOKEN, // This type is reserved for interchain tokens deployed by ITS, and can't be used by custom token managers.
        MINT_BURN_FROM, // The token will be minted/burned on transfers. The token needs to give mint permission to the token manager, but burning happens via an approval.
        LOCK_UNLOCK, // The token will be locked/unlocked at the token manager.
        LOCK_UNLOCK_FEE, // The token will be locked/unlocked at the token manager, which will account for any fee-on-transfer behaviour.
        MINT_BURN, // The token will be minted/burned on transfers. The token needs to give mint and burn permission to the token manager.
        GATEWAY // The token will be sent throught the gateway via callContractWithToken
    }
}
```

### Recommended Mitigation Steps

Apply these changes:

```diff
interface ITokenManagerType {
    enum TokenManagerType {
..snip
-        GATEWAY // The token will be sent throught the gateway via callContractWithToken
+        GATEWAY // The token will be sent through the gateway via callContractWithToken
    }
}
```

## [31] Wrong multiple `#[cfg(test)]` declarations in ITS Hub's `state.rs`

https://github.com/code-423n4/2024-08-axelar-network/blob/69c4f2c3fcefb1b8eb2129af9c3685a44ae5b6fe/axelar-amplifier/interchain-token-service/src/state.rs#L120-L273

```rust
#[cfg(test)]
pub(crate) fn remove_trusted_address(
    storage: &mut dyn Storage,
    chain: &ChainName,
) -> Result<(), Error> {
    TRUSTED_ITS_ADDRESSES.remove(storage, chain);
    Ok(())
}

// ... snip

#[cfg(test)]
mod tests {
    // ... (test module contents)
}
```

The ITS Hub's state.rs file contains multiple `#[cfg(test)]` declarations. This is also the only instance where this occurs in scope, which can be proven below:

<details>

105 results - 102 files

axelar-amplifier/ampd/src/block_height_monitor.rs:
71  
 72: #[cfg(test)]

73 mod tests {

axelar-amplifier/ampd/src/config.rs:
40  
 41: #[cfg(test)]
42 mod tests {

axelar-amplifier/ampd/src/event_processor.rs:
182  
 183: #[cfg(test)]
184 mod tests {

axelar-amplifier/ampd/src/event_sub.rs:
160  
 161: #[cfg(test)]
162 mod tests {

axelar-amplifier/ampd/src/health_check.rs:
56  
 57: #[cfg(test)]
58 mod tests {

axelar-amplifier/ampd/src/types.rs:
38  
 39: #[cfg(test)]
40 pub mod test_utils {

axelar-amplifier/ampd/src/asyncutil/future.rs:
101  
 102: #[cfg(test)]
103 mod tests {

axelar-amplifier/ampd/src/asyncutil/task.rs:
110  
 111: #[cfg(test)]
112 mod test {

axelar-amplifier/ampd/src/broadcaster/dec_coin.rs:
186  
 187: #[cfg(test)]
188 mod tests {

axelar-amplifier/ampd/src/broadcaster/mod.rs:
443  
 444: #[cfg(test)]
445 mod tests {

axelar-amplifier/ampd/src/broadcaster/tx.rs:
96  
 97: #[cfg(test)]
98 mod tests {

axelar-amplifier/ampd/src/evm/finalizer.rs:
116  
 117: #[cfg(test)]
118 mod tests {

axelar-amplifier/ampd/src/evm/verifier.rs:
117  
 118: #[cfg(test)]
119 mod tests {

axelar-amplifier/ampd/src/grpc/client.rs:
28  
 29: #[cfg(test)]
30 mod tests {

axelar-amplifier/ampd/src/grpc/server/ampd.rs:
125  
 126: #[cfg(test)]
127 mod tests {

axelar-amplifier/ampd/src/grpc/server/crypto.rs:
85  
 86: #[cfg(test)]
87 mod tests {

axelar-amplifier/ampd/src/handlers/config.rs:
159  
 160: #[cfg(test)]
161 mod tests {

axelar-amplifier/ampd/src/handlers/evm_verify_msg.rs:
223  
 224: #[cfg(test)]
225 mod tests {

axelar-amplifier/ampd/src/handlers/evm_verify_verifier_set.rs:
198  
 199: #[cfg(test)]
200 mod tests {

axelar-amplifier/ampd/src/handlers/mod.rs:
8  
 9: #[cfg(test)]
10 mod tests {

axelar-amplifier/ampd/src/handlers/multisig.rs:
188  
 189: #[cfg(test)]
190 mod test {

axelar-amplifier/ampd/src/handlers/sui_verify_msg.rs:
149  
 150: #[cfg(test)]
151 mod tests {

axelar-amplifier/ampd/src/handlers/sui_verify_verifier_set.rs:
153  
 154: #[cfg(test)]
155 mod tests {

axelar-amplifier/ampd/src/queue/msg_queue.rs:
44  
 45: #[cfg(test)]
46 mod test {

axelar-amplifier/ampd/src/queue/queued_broadcaster.rs:
171  
 172: #[cfg(test)]
173 mod test {

axelar-amplifier/ampd/src/sui/verifier.rs:
201  
 202: #[cfg(test)]
203 mod tests {

axelar-amplifier/contracts/axelarnet-gateway/src/client.rs:
61  
 62: #[cfg(test)]
63 mod test {

axelar-amplifier/contracts/axelarnet-gateway/src/contract.rs:
146  
 147: #[cfg(test)]
148 mod tests {

axelar-amplifier/contracts/axelarnet-gateway/src/executable.rs:
39  
 40: #[cfg(test)]
41 mod test {

axelar-amplifier/contracts/axelarnet-gateway/src/state.rs:
164  
 165: #[cfg(test)]
166 mod test {

axelar-amplifier/contracts/axelarnet-gateway/src/contract/query.rs:
42  
 43: #[cfg(test)]
44 mod test {

axelar-amplifier/contracts/coordinator/src/contract.rs:
95  
 96: #[cfg(test)]
97 mod tests {

axelar-amplifier/contracts/coordinator/src/contract/migrations/v0_2_0.rs:
50  
 51: #[cfg(test)]
52 mod tests {

axelar-amplifier/contracts/gateway/src/state.rs:
68  
 69: #[cfg(test)]
70 mod test {

axelar-amplifier/contracts/gateway/src/contract/query.rs:
32  
 33: #[cfg(test)]
34 mod test {

axelar-amplifier/contracts/gateway/src/contract/migrations/v0_2_3.rs:
85  
 86: #[cfg(test)]
87 mod tests {

axelar-amplifier/contracts/multisig/src/contract.rs:
193 #[cfg(feature = "test")]
194: #[cfg(test)]
195 mod tests {

axelar-amplifier/contracts/multisig/src/ed25519.rs:
12  
 13: #[cfg(test)]
14 mod test {

axelar-amplifier/contracts/multisig/src/key.rs:
321  
 322: #[cfg(test)]
323 mod ecdsa_tests {

486  
 487: #[cfg(test)]
488 mod ed25519_tests {

axelar-amplifier/contracts/multisig/src/multisig.rs:
47  
 48: #[cfg(test)]
49 mod test {

axelar-amplifier/contracts/multisig/src/secp256k1.rs:
12  
 13: #[cfg(test)]
14 mod test {

axelar-amplifier/contracts/multisig/src/signing.rs:
131  
 132: #[cfg(test)]
133 mod tests {

axelar-amplifier/contracts/multisig/src/state.rs:
114  
 115: #[cfg(test)]
116 mod tests {

axelar-amplifier/contracts/multisig/src/types.rs:
50  
 51: #[cfg(test)]
52 mod tests {

axelar-amplifier/contracts/multisig/src/verifier_set.rs:
82  
 83: #[cfg(test)]
84 mod tests {

axelar-amplifier/contracts/multisig/src/contract/migrations/v0_4_1.rs:
121  
 122: #[cfg(test)]
123 mod tests {

axelar-amplifier/contracts/multisig-prover/src/contract.rs:
119  
 120: #[cfg(test)]
121 mod tests {

axelar-amplifier/contracts/multisig-prover/src/events.rs:
47  
 48: #[cfg(test)]
49 mod tests {

axelar-amplifier/contracts/multisig-prover/src/lib.rs:
8  
 9: #[cfg(test)]
10 mod test;

axelar-amplifier/contracts/multisig-prover/src/payload.rs:
113  
 114: #[cfg(test)]
115 mod test {

axelar-amplifier/contracts/multisig-prover/src/contract/execute.rs:
416  
 417: #[cfg(test)]
418 mod tests {

axelar-amplifier/contracts/multisig-prover/src/contract/query.rs:
68  
 69: #[cfg(test)]
70 mod test {

axelar-amplifier/contracts/multisig-prover/src/contract/migrations/v0_6_0.rs:
87  
 88: #[cfg(test)]
89 mod tests {

axelar-amplifier/contracts/multisig-prover/src/encoding/abi/execute_data.rs:
78  
 79: #[cfg(test)]
80 mod tests {

axelar-amplifier/contracts/multisig-prover/src/encoding/abi/mod.rs:
70  
 71: #[cfg(test)]
72 mod tests {

axelar-amplifier/contracts/multisig-prover/src/test/mod.rs:
1: #[cfg(test)]
2 pub mod test_data;
3: #[cfg(test)]
4 pub mod test_utils;

axelar-amplifier/contracts/nexus-gateway/src/contract.rs:
73  
 74: #[cfg(test)]
75 mod tests {

axelar-amplifier/contracts/nexus-gateway/src/nexus.rs:
82  
 83: #[cfg(test)]
84 mod test {

axelar-amplifier/contracts/rewards/src/contract.rs:
168  
 169: #[cfg(test)]
170 mod tests {

axelar-amplifier/contracts/rewards/src/state.rs:
400  
 401: #[cfg(test)]
402 mod test {

axelar-amplifier/contracts/rewards/src/contract/execute.rs:
203  
 204: #[cfg(test)]
205 mod test {

axelar-amplifier/contracts/rewards/src/contract/query.rs:
63  
 64: #[cfg(test)]
65 mod tests {

axelar-amplifier/contracts/rewards/src/contract/migrations/v0_4_0.rs:
43  
 44: #[cfg(test)]
45 pub mod tests {

axelar-amplifier/contracts/router/src/contract.rs:
139  
 140: #[cfg(test)]
141 mod test {

axelar-amplifier/contracts/router/src/contract/execute.rs:
242  
 243: #[cfg(test)]
244 mod test {

axelar-amplifier/contracts/router/src/contract/query.rs:
36  
 37: #[cfg(test)]
38 mod test {

axelar-amplifier/contracts/router/src/contract/migrations/v0_3_3.rs:
50  
 51: #[cfg(test)]
52 mod test {

axelar-amplifier/contracts/service-registry/src/contract.rs:
178  
 179: #[cfg(test)]
180 mod test {

axelar-amplifier/contracts/service-registry/src/state.rs:
181  
 182: #[cfg(test)]
183 mod tests {

axelar-amplifier/contracts/service-registry/src/contract/migrations/v0_4_1.rs:
37  
 38: #[cfg(test)]
39 mod tests {

axelar-amplifier/contracts/voting-verifier/src/client.rs:
96  
 97: #[cfg(test)]
98 mod test {

axelar-amplifier/contracts/voting-verifier/src/contract.rs:
106  
 107: #[cfg(test)]
108 mod test {

axelar-amplifier/contracts/voting-verifier/src/events.rs:
283  
 284: #[cfg(test)]
285 mod test {

axelar-amplifier/contracts/voting-verifier/src/contract/query.rs:
145  
 146: #[cfg(test)]
147 mod tests {

axelar-amplifier/contracts/voting-verifier/src/contract/migrations/v0_5_0.rs:
105  
 106: #[cfg(test)]
107 mod tests {

axelar-amplifier/interchain-token-service/src/abi.rs:
252  
 253: #[cfg(test)]
254 mod tests {

axelar-amplifier/interchain-token-service/src/state.rs:
120  
 121: #[cfg(test)]
122 pub(crate) fn remove_trusted_address(

210  
 211: #[cfg(test)]
212 mod tests {

axelar-amplifier/interchain-token-service/src/contract/execute.rs:
161  
 162: #[cfg(test)]
163 mod tests {

axelar-amplifier/interchain-token-service/src/contract/query.rs:
27  
 28: #[cfg(test)]
29 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/counter.rs:
33  
 34: #[cfg(test)]
35 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/fn_ext.rs:
11  
 12: #[cfg(test)]
13 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/killswitch.rs:
75  
 76: #[cfg(test)]
77 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/permission_control.rs:
96  
 97: #[cfg(test)]
98 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/snapshot.rs:
60  
 61: #[cfg(test)]
62 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/threshold.rs:
154  
 155: #[cfg(test)]
156 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/utils.rs:
21  
 22: #[cfg(test)]
23 mod test {

axelar-amplifier/packages/axelar-wasm-std/src/verification.rs:
22  
 23: #[cfg(test)]
24 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/voting.rs:
409  
 410: #[cfg(test)]
411 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/msg_id/base_58_event_index.rs:
79  
 80: #[cfg(test)]
81 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/msg_id/base_58_solana_event_index.rs:
85  
 86: #[cfg(test)]
87 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/msg_id/mod.rs:
61  
 62: #[cfg(test)]
63 mod test {

axelar-amplifier/packages/axelar-wasm-std/src/msg_id/tx_hash_event_index.rs:
77  
 78: #[cfg(test)]
79 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/nonempty/string.rs:
61  
 62: #[cfg(test)]
63 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/nonempty/timestamp.rs:
25  
 26: #[cfg(test)]
27 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/nonempty/uint.rs:
126  
 127: #[cfg(test)]
128 mod tests {

axelar-amplifier/packages/axelar-wasm-std/src/nonempty/vec.rs:
41  
 42: #[cfg(test)]
43 mod tests {

axelar-amplifier/packages/events/src/event.rs:
113  
 114: #[cfg(test)]
115 mod test {

axelar-amplifier/packages/evm-gateway/src/lib.rs:
143  
 144: #[cfg(test)]
145 mod test {

axelar-amplifier/packages/report/src/loggable.rs:
153  
 154: #[cfg(test)]
155 mod tests {

axelar-amplifier/packages/router-api/src/primitives.rs:
464  
 465: #[cfg(test)]
466 mod tests {

~/.cargo/registry/src/index.crates.io-6f17d22bba15001f/cw-storage-plus-1.2.0/src/map.rs:
332  
 333: #[cfg(test)]
334 mod test {

~/.cargo/registry/src/index.crates.io-6f17d22bba15001f/error-stack-0.4.1/src/lib.rs:
473  
 474: #[cfg(test)]
475 mod tests {

</details>

From the search results across scope it's evident that only in the hinted instance in scope do we have double declaration of the tests.

### Impact

Wrong code.

### Recommended Mitigation Steps

Remove the first instance of `#[cfg(test)]`.

***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
