#### Ownership

In Cyphr, transferable is cryptographically implementable via key change,
but recording such changes in a ledger potentially results in human unreadable
transactions. Also, authorities may prohibit key updates to keys outside of the
principal, making transfer impossible.

Transfer ambiguity: For example, a comment could be updated to be signed by a
new key, but that would be ambiguous: was is a transfer or just as a result of a
key update? For that reason, updates with new keys outside of principal should
fail and transfer explicitly used for transfer.

##### Self-Sovereign Philosophy

###### Self-Ownership Philosophy in a Cryptographic System

There are three main categories of ownership:

1. Possess the private keys (Private Key Possession)
2. Possess the data (Data Possession)
3. Right to mutate state: `create`, `delete`, `update` (Right)

These three can be summarized as three points: **Keys, Data, Right**. The
protocol seeks to maximize user ownership across all three dimensions:

Keys → Self-custody, multi-device, revocation, recovery paths.
Data → Portable exports, optional self-hosting, minimal service lock-in (via MSS).
Rights → AAA replaces bearer tokens; verifiable authorship/actions without centralized session state.

**Private Key Possession** is important in cryptography. Cryptographic systems
are implemented using key possession. (Not your keys, not your crypto.)

**Data Possession** - For non-encrypted data: Possession generally equates to
ownership, as anyone with access can read/copy/use it.
For encrypted data: Ownership is tied to possession of decryption keys (which
may overlap with Private Key Possession). Encrypted data hosted by third parties
(e.g., for availability/security) does not imply loss of ownership if keys
remain user-controlled.

**Right** is relevant for authorship (comments, user history) and where
ownership is tracked on a ledger (e.g., bitcoin). Right is proven in a
cryptographic system using private keys and PoP.

Cyphr seeks to help users own their keys, data, and rights.

##### Natural Ownership

The originating Principal is the **natural owner** of its actions. For example,
the principal that creates a comment `comment/create` is the natural owner of
that comment, and has exclusive rights for future mutations: `comment/update`,
`comment/delete`, and `comment/upsert`. Systems implementing AAA must give
special attention to items with natural ownership properties.

###### Ownership Right Semantics

TODO Perhaps:
ownership is proven by the latest valid transfer chain. Ownership = latest valid transfer chain

`typ`s:

```
cyphr.me/ownership/claim/create
cyphr.me/ownership/transfer
ownership/transfer-ack
```

TODO multiownership

Perhaps an item itself can be represented as a Principal. Abstract things themselves have a chain.

"smart contracts" are supported by level 5+
Verifiable without full blockchain, Off-chain data friendly
No native "minting fee" or gas
No miner, validator race, or fee market
Revocable/revocable keys
Soulbound-like: set transferable=false