








CURRENT DRAFT IS IN ZAMI'S PRIVATE WORK DIR.  THIS IS A COPY













# Semantic Merkle Trees
### zamicol and nrdxp
### 20260712

## Abstract
As more Merkle tree variants are defined, the need for general categorical
hypernyms is apparent.

A semantic Merkle tree is an structured Merkle tree where specific interior
nodes carry semantic meaning.  Semantic structure transforms the pure
cryptographic commitment into a structure that communicates data interpretation,
while preserving all the verifiability properties of a traditional Merkle tree.

We also describe arity, null support, append only (accumulators) and define two
novel Merkle primitive operations, singleton promotion and collapse.

## Introduction 
A **Merkle tree** (MT) is a hash tree in which each leaf node holds a digest,
and each internal node holds the digest of the concatenation of its children.
The root digest provides a compact, tamper-proof commitment of the entire
dataset, enabling efficient membership proofs in logarithmic time.

Although not strictly binary, the traditional MT is often described as binary and
lacks internal semantic meaning or structure.

## Structure Merkle Trees
A **structured merkle tree** is a Merkle tree where some interior nodes are
organized according to specific aggregation rules.  This may be done for
aggregation or performance reasons. For example, both Merkle Mountain Ranges and
Merkle Mountain Belts are example of structure Merkle trees.

# Arity
A structure Merkle tree may define dynamic arity.  Arity is the number of
children a parent node is permitted.  Trees or nodes may be either k-ary or
n-ary.  K-ary is a static arity for the entire tree.  N-ary is a dynamic arity
on a per node basis.

 - **k-ary** - A tree with a static arity.  For example, binary.  A child node
may have zero children, in which case it is a leaf, one child, in which case it
is "unbalanced", or two children.
 - **n-ary** - A tree with a dynamic arity. A child node may have zero to many
nodes. A node with zero children is a leaf, a node with one to many children is
an inner node. 

A traditional MT is binary, that is k-ary of 2. A SMT may have internal semantic
meaning and may define explicit arity. MT's also do not define dynamic internal
strucutre.  The entire tree follows a simple algorithm.  For example, the MT
defined by RFC 9162 is a simple "left filled, append only" algorithm.

In practice, cypherary (base 0) is incapable of communicating information. Unary
(base 1) is equivalent to a hash chain. Since unary doesn't concatenate, it has
fewer useful properties, although it can still be used for commitments and
communicate depth information.  Binary (base 2) is the first generally useful
base, and ever base after.

 
## Semantic Merkle Tree
In a traditional MT, only leaves may have semantic meaning. That is, the leaves
are assumed to represent a concrete asset while inner nodes exist purely for
cryptographic aggregation and have no semantic meaning. Consequentially, the
only variable determining the MTs shape is the number of nodes. All MTs of the
same size share the same shape.

A **Semantic Merkle Tree (SMT)** (or substituting the eponym, a **Semantic Hash
Tree**) is a structured variant of a traditional Merkle tree in which internal
nodes and leaves, may carry explicit semantic meaning beyond aggregation. While
traditional Merkle trees treat nodes as opaque hashes, a SMT may define
domain-specific structure and labeling, enabling richer verification, efficient
incremental updates, custom integrity and membership proofs, and protocol-level
reasoning.

A Semantic Merkle tree is structured.  Instead of applying a single aggregation
algorithm to the entire tree, specific nodes may have their own rules.  For
example, a some nodes may allow addition and deletion while other nodes may be
append only.

# Parent Digests Do Not Need to Know the Number of Children
Critically, the SMT takes advantage of an important property: a parent digest is
already endowed with count information.  The number of children is contained
within the hash


A digest does not explicitly communicate how many children it contains outside
of a proof where the appropriate children are given.  A prover must provide the
current number of children.  Although opaque, a cryptographic digest not only
protect content integrity, but also the "meta" data of the number of children.
Although arity may affect performance, arity does not need to be rigidly define
for the security of a Merkle tree.  Arity is implicitly protected.


As long as a MT primitive supports 

1. dynamic arity
2. arbitrary inserts

many diverse merkle tree structures may be generated.  

Further, 3. deletes may be required for some structures, although the creation
of a new tree is equivalent to deletes.

It is the suggestion of this paper that tree library primitives provide an
interface for dynamic arity and arbitrary inserts. 


## Structured Vs Semantic
MMRs are a type of structured merkle trees, but are not semantic Merkle trees
since internal nodes are not necessarily imbued with semantic meaning.

Merkle Patricia Tries, as implemented by Ethereum, are semantic as extension
nodes, branch nodes, and leaf nodes directly encode semantic organization of
keys.

Git's Merkle DAG semantically represent directoyy listings, and thus are semantic.





## Singleton Promotion and Collapse
We also introduce two additional primitive operations to the Merkle tree,
singleton promotion and collapse.

Arity opens up a new question, are duplicate node legal?  What happens when
there are duplicate nodes?

Rehashing 

We also consider obfuscation. 


**Singleton promotion** is the elevation of a Merkle tree node digest to a
parent slot, without re-hashing, when a tree component has only one node value.

**Collapse** is the elevation of a child node's digest, without re-hashing, to
the parent when children are of equal value.

Promotion an collapse are recursive; items deep in a tree can be promoted to the
root level. For example, when a principal has only a single key, the key's `tmb`
is promoted to KR without additional hashing.

**Singleton promotion** is the elevation of a Merkle tree node digest to a
parent slot without additional hashing when a tree component has only one node
value.  Promotion isn't obvious in the binary paradigm, but from a n-ary
perspective it becomes more obvious. 

Collapse When children are of equal value, the parent assumes the value of the
children without re-hashing.  Again, this is a consequence of n-aryness and
arbitrary structure.  If a node can be inserted anywhere in the tree, what
happens when two nodes share the same value?  While simple binary MT's may 

Promotion an collapse are recursive; items deep in a tree can be promoted to the
root level. For example, when a principal has only a single key, the key's tmb
is promoted to KR without additional hashing.


 promotion/collapse rules, and verifiable relationships that reflect the logical
organization of the data. This enables richer verification, more efficient
incremental updates, and protocol-level reasoning about state.

## Nulls
Null promotion - A consequence is the "null boundary", where populated nodes
meet up with non-populated (null) nodes. Generalized singleton promotion isn't
explicitly supported with the current draft, but it can be trivially added.
Singleton promotion isn't as useful in a binary structure.

## Nomenclature
### Log Vs. Tree
We propose and employ the nomenclature that accumulators be termed "log" instead
of "tree".  For example, a Epoch Merkle Log (EML) is an accumulator.

### Advise against "inode" nomenclature
We advise against the "inode" nomenclature since file system already use the
term for a very different structure: the index node. Instead we favor "branch",
"inner node", and "subtree" in the appropriate contexts.

## Impetus
While designing [Cyphr](https://github.com/Cyphrme/Cyphr), we discovered
dynamic, semantically defined Merkle trees were lacking description.  Our aim in
this paper is to fill in those gaps.

## References
Merkle, Ralph C. *A Digital Signature Based on a Conventional Encryption Function*.
CRYPTO 1987. Available:  
https://people.eecs.berkeley.edu/~raluca/cs261-f15/readings/merkle.pdf

Todd, Peter. *Merkle Mountain Ranges*. OpenTimestamps Server Documentation,
October 30, 2012. Available:
https://github.com/opentimestamps/opentimestamps-server/blob/4e273b26d7bc5e358a2383eb73535c5253b5e5db/doc/merkle-mountain-range.md
See also https://x.com/Zamicol/status/2074622376256606577

### Related works

Wood, Gavin. *Ethereum: A Secure Decentralised Generalised Transaction Ledger*.
2014 (continuously updated). Appendix D describes the Modified Merkle Patricia
Trie. Available: https://ethereum.github.io/yellowpaper/paper.pdf

Kuszmaul, John. Verkle Trees. PRIMES-USA, 2018. Available:
https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf

Cevallos, Alfonso, Hambrock, Robert, and Stewart, Alistair. *The Merkle Mountain
Belt.* arXiv preprint arXiv:2511.13582, November 17, 2025. Available:
https://arxiv.org/abs/2511.13582

Bayardo, Roberto. *Merkle Mountain Ranges for Performant Data Authentication*.
Commonware Blog, February 13, 2025. Available:  
https://commonware.xyz/blogs/mmr

Bayardo, Roberto. *Grafting Trees to Prove Current State*. Commonware Blog, July
9, 2025. Available:  
https://commonware.xyz/blogs/adb-current

Bayardo, Roberto. *Honey, I Shrunk the Proofs!*. Commonware Blog, May 6, 2026.
Available: https://commonware.xyz/blogs/pyramid-mmb

