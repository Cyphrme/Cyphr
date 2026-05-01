# Level 2.5: Multi-Key (Transitional Multi-Key, Pre-Commit)

Level 2 is single key with atomic replacement while 3 is introduces a commit
chain with multiple keys.

This leaves a situation in-between that we call "2.5", multiple concurrent keys
with equal authority, but without a full commit chain or historical tracking.
This is a transitional level bridging single-key (Level 1) and full commit-based
multi-key (Level 3) enabling basic multi-device support while avoiding chained
commits.

"Level 2.5" is omitted from the Cyphr spec because it should not be implemented,
instead 3 directly should be implemented.  Level 3 commit prevents footguns that
level 2.5 causes. The following describes this 2.5 out of completeness. 

Level 2.5 has a implicit global state that isn't referred to be transactions. KR
is the MR of all `tmb`s; promoted to AR and then PR (similar to Levels 1-2).

Sharing history with 2.5 leans on trusted serves; revocations and other
mutations must be shared with all witnesses, an 0(n) problem, a design incentivizing implementers to
simply trust a service. Concurrent mutations may lead to races (which is left
to be resolved by services).

Upgrading to Level 3 occurs as normal.  A principal defines a targeted state and
commits that as the principal genesis.

**Level 2.5 Key Properties**
- All keys have equal authority (default weight of 1, no rules).
- Any active key can perform `key/create`, `key/replace`, or `key/revoke`
  operations, which results in a new KR (MR of the updated `tmb` set).
- All mutations must sent to all witness in order to keep state synced.

#### Adding a key

Example Transaction adding a key. If a `key/create` is accepted, the new KR
becomes the PR.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Existing key tmb
    "typ": "cyphr.me/cyphrpass/key/create",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M" // New Key
  },
  "sig": "<b64ut>"
}
```