# Conversion Tree

A Conversion tree is a type of a Multihash Merkle tree.  First we define
Multihash Merkle tree and then Conversion tree.  The Conversion Tree was
originally specified for Cyphr, but we later decided that EML was a better
overall implementation.  We detail it here for historical completeness.

The Conversion Tree assumes Coz, where specific cryptographic hashing algorithms
are associated with particular signing algorithms. 

## Conversion Tree MultiHash Merkle Root (MHMR)

The **MultiHash Merkle Root (MHMR)** algorithm computes digests for nodes in a
principal tree using multiple hashing algorithms.  

Each MHMR variant is computed with respect to a **target hash**. 

**General MHMR Computation**
Given an list of child digests (each child is a binary digest value computed
under some hash algorithm):

1. **Order** If unordered, sort the child digests in lexical byte order.  If
   ordered, use given order.
2. **Singleton promotion**:  If there is one child digest, the MHMR_H is simply
   the bytes of that child digest (no hashing occurs). Promotion is recursive.
3. **Hashing of Children**: By default binary concatenate the sorted child
   digest bytes in order.  For structured tree components, n-ary may be used.
   For binary, MHMR = H(A||B), ternary, MHMR = H(A||B||C), and on.



### Conversion Tree

A **Conversion tree** is a type of a Multihash Merkle tree.  A node may be
addressed by one to many algorithms; multiple hashing primitives may be used
concurrently by inner nodes.

Parent nodes use the matching algorithm of children when available. When
children are of the same algorithm, the same algorithm is used for the parent.

When a child and another child is of a different algorithm, the child is
**converted** first to the target hash. This step is termed conversion because
one hashing algorithm is dropped and converted to another at this point.

For example, in a Merkle tree with a SHA-384 node (A) and SHA-256 node (B), a
SHA-384 root is: MR_SHA384(SHA384(A), B). B's SHA-256 value is fed into the
hashing algorithm first before being inputted into the MR.



```text
                SHA-384 Root
               ┌─────────────┐
               │  MR_SHA384  │
               └──────┬──────┘
                      │
              SHA-384( A || B )
                      |
          ┌───────────┼───────────┐
          │                       │
          │               SHA-384(Node B) <- Conversion step
          │                       │
   ┌─────────────┐         ┌─────────────┐
   │   Node A    │         │   Node B    │
   │  (SHA-384)  │         │  (SHA-256)  │
   └─────────────┘         └─────────────┘
```


A consequence of supporting multiple hashing algorithms, for each algorithm, a
node may have an identifier for that hashing algorithm. There are two ways to
implement a conversion tree: variant trees must be labeled with a digest or the
node must label digests explicitly with an algorithm.

Perhaps surprisingly, because conversion occurs at the node level, the parent
node does not require knowledge of the child node's conversion.  Only at the
time of verification/proof is the child node's value required, where conversion
is evident.  This is what allows hashing algorithms to be dropped or added as
required by the application.

For Cyphr, the target hash is determined on a per commit basis, using the hash
algorithms referenced by the principal's keys as supported primitives.  When
multiple hash algorithms are referenced, implementations compute a MHMR variant
digest for each hash. When an algorithm is removed from reference in the key
list (a principal's KT), its MHMR variant is no longer generated for new
commits.  Since commits are organized as a binary a tree, dropped algorithms are
converted deep in the tree, removing the need for the continued algorithm
support. In this way Cyphr supports embedded nodes and upgrades, values from one
digest algorithm may be converted as input to another. 

Hashing properties:
- **No rehashing of children**: Inner digests are fed directly into the parent
  hash function as raw bytes (unless being converted, where the value is hashed
  first).  
- **Padding** Padding follows the primitive specification, if none is provided,
  pad with zero bytes.
- **Byte-order determinism**: Given order or lexical byte sorting ensures
  consistent ordering regardless of how children were labeled or enumerated.

**Conversion MHMR Examples**

| Case       | Children                 | Target   | Computation    | Result   |
| ---------- | ------------------------ | -------- | -------------- | -------- |
| Single     | B (SHA-256)              | SHA-384  | (promotion)    | 32 bytes |
| Same alg   | C, D (both SHA-256)      | SHA-256  | SHA-256(C||D)  | 32 bytes |
| Diff. algs | A (SHA-384), B (SHA-256) | SHA-384  | SHA-384(A||B)  | 48 bytes |


N-ary Example: 
Inputs: SHA-256, SHA-384, SHA-512
Targets: SHA-384, SHA512:

SHA-384(A||B||C) with an output of 48 bytes 
SHA-512(A||B||C) with an output of 64 bytes

## Explicit vs implicit conversion
Described so far 

## MHMR Security
Although outside the scope of this document, security is bounded by weakest
hash.  The strength of any MHMR is limited by the weakest hash algorithm
appearing anywhere in the subtree below.

**Conversion Security Considerations**
Conversion is not ideal, but is unavoidable for pluggability, recursion, and
embedding. Implementors must be aware that inner nodes may have different
security levels than parent nodes. Algorithm diversity aids durability but
risks misuse. For a particular node, security is bounded by the weakest link.
For uniform security, keys from one strength category may be used.

## Native Digest
Nodes may have a native hash or no native type.
- Key Tree: The native hash for a key node is the hash matching the key's coz
  type.
- The native hash for a node added by a commit is the hash matching the key's
  type.
- For commit with multiple hashes (a commit where two keys signed with hashes of
  different types), the node has two native hashes.
- Nodes may be given explicitly multiple hashes as required.  Each algorithm
  added is tracked by the implementation. 

**Conversion Example**: For a SHA384 tree containing a node that is SHA256 only
(for example, for an ES256 key, an opaque embedding, or any node with a
different hashing algorithm), the node is converted into a SHA384 node.

The ES256 Key node:

```json
{"SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":{<key data>}}
```

The ES256 key node is converted to SHA384:

```json
{"SHA384:NLDDkOyBHNVG4H6yHwSf8AwvI82B-tRhleeuBhYR4LCdvP9Is2-HjXMbllTv0NJk":""}
```

## Conversion Vs. EML: Comparison to EML

**Intermixing**
EML has one logical tree for each algorithm, and only the roots are combined.

The Conversion tree intermixes algorithms deeply. From a given root it may not
be apparent that multiple hashes appear in the tree unless provided as metadata.

**Hash Identification**
EML: Hashing algorithm labeling is global to a tree.
Conversion: Each supported algorithm for a node is labeled.

**Nulls**
Conversion trees do not use nulls.
EML uses nulls to represent 

**Collapse and Singleton Promotion**
Both use collapse and singleton promotion.

**Binding Root** EML requires a binding root.  Cyphr implements the binding that
when an algorithm is dropped the MR for a specific hash may be dropped from the
binding root. Implementation should keep a pointer to the last commit where a
particular digest was referenced.  

The historical tree may be considered to be filled in with "nulls" for future
records. 


## See Also
- Document labled 20260610_conversion_vs_eml_discussion.md
- The EML document currently at: https://eml-paper.netlify.app


