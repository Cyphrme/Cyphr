# Level 2.5: Multi-Key (Transitional Multi-Key, Pre-Commit)
Level 2 has multiple concurrent keys with equal authority, but without a full
commit chain or historical tracking. This is a transitional level bridging
single-key simplicity (Level 1) and full commit-based multi-key management
(Level 3). It enables basic multi-device support while avoiding the overhead of
chained commits.

Level 2 has a implicit global state that isn't referred to be transactions.

KS is the Merkle root (MR) of multiple `tmb`s;
promoted to AS and then PS (similar to Levels 1-2).
- **Limitations**: No history; revocations and other mutations are not tracked
  historically, and concurrent mutations may lead to races (resolved by services
  via timestamp or nonce). 

Multi-device setup, or simple services not requiring audit trails.

#### Key Properties
- All keys have equal authority (default weight of 1, no rules).
- Any active key can perform `key/create`, `key/replace`, or `key/revoke`
  operations, which result in a new KS (MR of the updated `tmb` set).
- No `pre` field required for transactions (unlike Level 3+), as there is no
  chain. Instead, transactions target the current KS directly.
- Implicit promotion: If only one key remains, reverts to Level 2 behavior.
- To enable: A Level 2 principal performs a `key/create` to add the first
  additional key, promoting to Level 2.5 automatically.

#### Adding a key

**Example Transaction: Adding a Key**
```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",  // Existing key tmb
    "typ": "cyphr.me/cyphrpass/key/create",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"// New Key
  },
  "sig": "<b64ut>"
}
```
- The new KS is computed as MR of the sorted `ks` list.
- Services validate: Signature from current KS, nonce uniqueness, no duplicates.
- If accepted, the new KS becomes the implicit PS.

Use `key/revoke` with `rvk` timestamp on a specific `tmb`. The transaction
includes the full updated `ks` list excluding the revoked key.

#### Upgrade to Level 3
- Perform a commit genesis with `pre` referencing the current KS.
- This establishes the chain and enables historical tracking.

#### Security Considerations
- **Race Conditions**: Without a chain, concurrent additions from different
  devices may conflict. Services should enforce a short acceptance window based
  on `now` and reject duplicates via nonce.
- **No Audit Trail**: Lost history means revocations are not verifiable
  retroactively; rely on services for dispute resolution.
- **Downgrade Risk**: If all but one key is revoked, implicitly demotes to Level
  2.
- Implementations should encourage upgrading to Level 3 for any principal with
  more than 2-3 keys or frequent mutations.