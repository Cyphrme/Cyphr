# Sketch: Verifiable Log Commit Model

Working sketch — collaborative discussion with Zami.

---

## Core Idea

The principal maintains an **append-only Merkle log** of commits. The principal is their own log operator. Witnesses verify against signed log roots.

## Structure

### Leaf

Each commit appends **one leaf** to the log. A leaf is the commit's mutation content:

```
leaf_i = MR(mutation czds in commit i, ordered)
```

### Log Root (= CS)

CS is the **cumulative Merkle log root** after N commits:

```
N=1: CS = leaf₀                                    (promoted)
N=2: CS = H(leaf₀ ∥ leaf₁)
N=3: CS = H(H(leaf₀ ∥ leaf₁) ∥ leaf₂)
N=4: CS = H(H(leaf₀ ∥ leaf₁) ∥ H(leaf₂ ∥ leaf₃))
```

### PS

Unchanged: `PS = MR(AS, CS, DS?)`

### Commit (Signed Tree Head)

The commit is a **signed assertion** about the log state. It lives in `txc`, separate from mutations:

```json5
{"txc": [{
  "pay": {
    "alg": "ES256",
    "tmb": "<signing key>",
    "now": 1736893000,
    "typ": "cyphr.me/cyphrpass/commit/create",
    "commit": "<binding digest>"  // see below
  },
  "sig": "<b64ut>"
}]}
```

### Commit Binding (replaces PTD)

The self-reference problem persists — the commit can't sign a digest that includes itself. The binding covers everything except the commit's own czd:

```
commit = MR(prev_CS, fwd, leaf)
```

Where:
- `prev_CS` = log root before this commit (replaces `pre`)
- `fwd` = forward PT (resulting state sans CS)
- `leaf` = MR(this commit's mutation czds)

> **vs current model:** `PTD = MR(pre, fwd, TS)` → `commit = MR(prev_CS, fwd, leaf)`.
> Structurally identical, but `prev_CS` is a log root rather than PS.

---

## Witness Resync (Consistency Proof)

**Scenario:** Witness has trust anchor at commit M. Principal is now at commit N.

```
Witness                              Principal
   |                                     |
   |-- "My anchor is CS_M (pos M)"  ---->|
   |                                     |
   |<-- consistency_proof(M, N)    ------|
   |<-- leaves M+1..N              ------|
   |<-- signed CS_N                ------|
   |                                     |
   |  1. Verify consistency proof:       |
   |     CS_M is a prefix of CS_N        |
   |     (O(log N) hashes)               |
   |                                     |
   |  2. Replay new leaves only:         |
   |     Verify sigs, authorization      |
   |     Compute resulting state         |
   |                                     |
   |  3. Accept CS_N as new anchor       |
```

**What this replaces:** Current §17.2 resync process + §23 state jumping. Both collapse into "verify consistency proof + replay new leaves."

**Key property:** The consistency proof guarantees everything before M is untampered **without replaying it**. The witness only processes new commits.

---

## Inclusion Proof (Selective Disclosure)

**Scenario:** Third party wants to verify commit K happened.

```
Third Party                          Principal
   |                                     |
   |-- "Prove commit K exists"   ------>|
   |                                     |
   |<-- leaf_K                    ------|
   |<-- inclusion_proof(K, N)    ------|
   |<-- signed CS_N              ------|
   |                                     |
   |  1. Verify inclusion proof:         |
   |     leaf_K is in log with root CS_N |
   |     (O(log N) hashes)              |
   |                                     |
   |  2. Verify leaf_K contents:         |
   |     Check transaction signatures    |
```

**What this enables:** Prove a specific key was created, revoked, or action occurred, without revealing the entire commit history. Useful for authentication, auditing, and privacy.

---

## State Jumping (Collapsed)

**Current model:** Custom `state-jump` transaction type (§23) with revocation checks, multi-jump, etc.

**Log model:** State jumping IS a consistency proof.

```
1. Client has anchor at CS₅
2. Wants to jump to CS₅₀
3. Principal provides: consistency_proof(5, 50) + state at 50
4. Client verifies proof → trusts CS₅₀ extends CS₅
5. Client spot-checks signing key is active at CS₅₀
6. Done — no custom transaction type needed
```

**Caveat:** Still need to verify the jumping key is active at both endpoints. But that's a simple KS membership check, not a custom protocol mechanism.

---

## What Simplifies

| Current Model | Log Model |
|---|---|
| TS = MR(mutation czds) | leaf = MR(mutation czds) — same computation, one name |
| TCS = MR(commit czds) | commit czd is just the signed tree head — no separate MR needed |
| CS = MR(TS, TCS) | CS = log_root (cumulative, well-defined algorithm) |
| §23 State Jumping (custom) | Consistency proof (standard) |
| §17.2 Resync (bespoke) | Consistency proof + new leaves (standard) |
| `pre` concept | `prev_CS` (previous log root) — semantically clearer |

## What Persists

| Concept | Why |
|---|---|
| Commit binding digest | Self-reference constraint is data-structure-agnostic |
| `fwd` (forward PT) | Optional but useful for result commitment |
| `txs` / `txc` separation | Mutations go in log as leaves; commit is signed tree head |

## Open Questions

1. **What exactly is a leaf?** Just MR(mutation czds)? Or does it include resulting AS/DS for richer proofs?
2. **Does `prev_CS` replace `pre` entirely?** Or do we still want `pre` (prior PS) for chain-level verification?
3. **Log tree algorithm:** Standard RFC 6962 Merkle tree? Or Cyphrpass's existing MR with implicit promotion?
4. **Storage cost:** Witnesses need to store intermediate tree nodes for proof generation. How much overhead? Zami Says: Log(n) overhead since new binary MR's never change
5. **Does this change multihash?** CS is now cumulative — do we compute MHMR variants of the full log root at each commit?
