```text
Principal Root (PR)
│
├── State Root (SR) ───────────────── [State]
│   │
│   ├── Auth Root (AR) ────────────── [Authentication]
│   │   │
│   │   ├── Key Root (KR) ─────────── [Public Keys]
│   │   │
│   │   └── Rule Root (RR) ────────── [Permissions & Thresholds]
│   │
│   └─── Data Root (DR) ───────────── [Data Actions]
│
└── Commit Root (CR) ──────────────── [State Mutations]
```

The **principal root** (PR) is a hierarchical structure of cryptographic
Merkle roots over the PT nodes and is calculated for each commit. The first PR
is the **principal genesis** (PG).


A principal is organized as three
primary components: **authentication**, **commit**, and **data**.

A principal is organized as three
primary components: **authentication**, **commit**, and **data**.
  (SR is implicitly promoted to PR since CR is empty, and the first PR is PG.)


  ; A MALTR is a MR but not
  all MR are MALTRs. applies a
  more strict implementation of the Canonical Root Algorithm where 

  If order
   is not otherwise given, lexical byte order is used


In this model, trusted centralized user identity
services should be actively deprecated. 



Commits are ordered and new commits are appended sequentially from the left,
maintaining a dense prefix with no gaps, following the growth pattern used in
RFC 9162.


 When CT exists (level 3+), PR is the MR of PT
including the last commit (commit id), so that PR = MR(SR, CR).





# Multihash edit:

Multihash identifiers are calculated on a per commit
basis for each hash algorithm referenced by the principal in KT at the time of
commit. 

- Digests are computed for all hashing algorithms referenced in KT (keys,
  embeddings).


  In summary:

- MT nodes are referenced by multihash identifiers.

- When an algorithm primitive is removed, its hash is no longer computed. When a
  primitive is added, its algorithm's variant begins computation.
- Cyphr makes no

 relative security judgements. All variants are considered
  equivalent.

  ithm associated with a current component in KT.

















# DONE TODOs/Deprecated todos:
  - Commit coz bundling/finality.  The commit transaction explicitly bundles the
  commit, but since there are multiple cozies for the commit transaction itself
  it needs a bundle identifier.
- Historical Mode - past hashing algos that are no longer supported, the trust
  of the payloads should not depend upon the hashes themselves. This property
  should likely be generic anyway, so 
- In JSON, State is upper case, plural is lower case.
- I think we can remove pinning