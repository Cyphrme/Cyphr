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