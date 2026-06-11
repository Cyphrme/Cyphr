## Intro, MALT and EML:
#### 2.2.10 MALT and EML
MALT and EML are specific types of Merkle trees. See section [Commit](#4-commit)

Importantly MALT enables succinct inclusion and consistency proofs, which
increases client performance.  A MALT root is termed a **MALTR**. The commit
tree (CT) up to the commit boundary is organized as a MALT in order to take
advantage of these properties.

RFC 9162 MALT also includes a hash prefix for internal nodes and leaves for
"second preimage resistance", and consequentially nodes are not ever equal to a
regular Merkle tree. Although MALT is used in this document, alternatively a
Epoch Merkle Log (EML) may be used.  MALTs are also sometimes colloquially
termed "certificate transparency (CT) trees".

## Next Evolution: Conversion Tree and EML
**Conversion tree**: one unified tree.  When a hashing alg is dropped, it's
converted that that boundary to another supported hashing alg through a step
called "conversion". 

**EML**: Instead of conversion, it uses projection.  Null nodes are allowed on a
per hash basis, but a node must be populated in one of the projections.

Arrow with NEML Mixing: 
-  Minimally, pre is all digest roots referred to in that commit.  Ideally, NEML
   provides that since NEML itself needs that function.

CT's MALT uses coz actions as leaves, including the commit cozies. 

Currently, the MT specified by the spec is:

1. Unbalanced. Some branches/subtrees go many layers deep (with multiple levels
   of internal nodes/children), while others have leaves directly attached
   higher up (shallow or "direct" leaves relative to their peers)
2. Arbitrary order.  Some leaves have an arbitrary order, as given by the
   principal, while others are ordered by now.  Different order rules apply to
   different node types, so verifying clients must be aware of node type and
   order.
3. Promotion, including null promotion
4. No prefix.  (Cyphr already has length extension protection, and content
   addressing is more important.  For our use, length extension prevention
   inside of the Merkle tree is an anti-pattern.)

## Adjacent Concerns:
- **Commit Boundary**: The commit boundary up should be a logical binary tree,
while from the commit boundary below must be n-ary.  This is an application
detail; as long as the tree is n-ary it is not an implication detail.(Since
n-ary is hypernym of binary, an n-ary tree is inclusive of binary MT's.) 

- **Multi-Alg** - Multi-alg must be supported. Nodes may be referenced by one to
many algs, but not necessarily by a given alg.

- **Mixing must be via hashing algorithm** Need some sort of mixing for 1.
security and 2. relating nodes from multi-hash

- Thinking about **Conversion**. Conversion is inputting one digest from one
algorithm into another. Conversion provides important properties: state mixing,
and the ability to drop an algorithm.   In the conversion tree, when an alg is
dropped, it becomes converted at the last present node into other digest
algorithms.  All hash algorithms have complete trees, but subtrees may not be in
the root algorithm if it wasn't present Conversion translating between different
hash algorithm trees.

- **N-ary has "singleton promotion"** - This isn't as relevant in binary trees,
  it becomes much more useful in n-ary trees. 

- **Post Facto Digest additions** A historic node, which is given a hash, say
because its a resource, should be updated to root.

- **No prefixes** In all cases, we need no prefixes (what RFC 9162 calls
  "prefixes". Universal CCIDs are vastly more important, prefixes don't actually
  solve the architectural problems they claim to solve.  They simply act as an
  identifier between inner nodes and leaves, an anti-pattern for out use and
  also directly contradicts the utility of singleton promotion.

- Interplay between resource and data node hashing algorithm.  Coz is signed
  only by one alg.  Resources may be referenced by many algs.  If Coz itself
  needs multi-hash, CAD may be used.

 - Even if we use one data structure for CT, we still need an n-ary arbitrary
   Merkle tree for ST (AT and DT) and ultimately PT


## Zami thought: **Multi-hash Conversion, N-ary, Merkle Tree**
- **Proofs**: Inclusion and consistency. (No such thing as projection proof.
  Conversion just needs support of each hashing algorithm.  This is the "binding
  proof", at individual nodes)
- **Assumes only hashing algorithms** good, there's only a single class of
  cryptography for this data structure.
- **Arrow gets pre-mixed** Arrow gets a pre-mixed PR which is in one to many
  algs, one to many may be signed.
- **Ordered**: Nodes have an order as specified by principal.
- **Directionality** - Input of the ordered nodes matters.  H(X,O) is not equal
  to H(O,X)
- **Left dense filled**: Leaves are added from left to right with no gaps.
- **Unbalanced**: The tree is not guaranteed to be symmetrical. Minimally, a
node may have a single child, which causes the whole of the tree to lack perfect
symmetry.
- **CT Append Only**: The datastructure is only forward mutable.  Past nodes are
  immutable (with the exception of hash addition on resources).  For ST we need
  mutation, although running ST in "append only" mode is a nice future goal.
- **Singleton Promotion** A node with only one child assumes the value of the
  child. (Null promotion can be trivially/explicitly supported.) (This also
  requires an arbitrary structure, where depth must be encoded somehow, which is
  possible using just digests themselves.)
- **n-ary**: A node may have one to many children. Not binary, although CT from
  TR up is isomorphic to a binary tree.
- **Arbitrary structure**: A node may have many repeating children (due to
  promotion).  Although the tree can stop calculation at a promoted node, the
  implementation must minimally preserve height information.  Other information
  like node labeling may be meta data.
- **Arbitrary height** Past the commit boundary, a subtree may be shallow or
  deep as needed.
- **Conversion**:  Multi-alg supported, Mixing through conversion at the time of
  an alg drop.  However, cryptographic digest security may be mixed.  The only
  way to avoid mixing security is to use a single hashing algorithm.
- **Tree Mixing**: There's only one tree. Cryptographic state mixing (binding)
  is handled by conversion. Since there is one tree, nodes always exist,
  although they may only be address by a subset of digests.
- **State Mixing (binding)**: Same mechanism as Tree mixing, conversion.
- **One tree**: The single Principal tree is inclusive of all algs
- **Node hash n-ary addressing** - A node may be addressed by many algorithms
- **No Rank** Originally I feared principals can specify rank, where algs are
  selected on conversion when dropped.  Then I figured out this isn't needed;
  simply convert to each supported alg.  Rank was dropped form the spec about
  two months ago.
- **No Prefix; pure digest**  Cryptographic content identifiers is a killer
  feature.  (The RFC 9162's architectural justification is nonsense, other there
  may be merit for other reasons.  However, for our use it is an anti-pattern.)
- **Opacity** - A node doesn't know necessarily know the number of its children
  unless disclosed. A node may be a leaf or an inner node, it's unknown until
  proven.  Embeddings may be subtrees or concrete items, this is supported.
- **No Activation/Signed tree head** Only arrow is signed, this is external to
  tree primitive.
- **Individual nodes hash alg labeling** - Hash alg needs to be known.
- **Node equivalency** through single tree.
- **Node Multi-hash, Leaf Multi-hash** Each node may have multiple hashes, they
  may be given multiple hashes after the fact.  This applies to leafs and inner
  nodes.
- **Digest equivalency proofs** - Hash algo node sequence equivalency is
  provable using cryptographic digests.
- **Post Facto Digest** additions require retroactive recalculations.  Hash
  roots will be recalculated.


## Nrdxp thought: **Binary EML**
- **Proofs**: Inclusion and consistency.  Cross-algorithm projection proofs are
  implemented via STH (bad)
- **Assumes digital signing algorithms** bad, we don't want to introduce a new
  class of cryptography for this data structure.
- **Arrow** handles relating digests to one another where `pre` = H(MR0_H0,
  MR0_H1, etc...)
- **Ordered**
- **Directionality**
- **Left dense filled**
- **Unbalanced**
- **CT Append Only**
- **N-ary Null promotion** - A consequence is the "null boundary", where
  populated nodes meet up with non-populated (null) nodes. Generalized singleton
  promotion isn't explicitly supported with the current draft, but it can be
  trivially added.  Singleton promotion isn't as useful in a binary structure.
- **Binary**: A node can have no more than two children.  As opposed to n-ary.
- **Can't do CT down** - an n-ary MT is required for TR, ST, AT, DT, and PT.
  Only CT is considered for EML.
- **Not arbitrary structure**, defined structure - Nodes are not allowed to be
  constructed as desired; strict binary tree.  A non-binary tree could be
  projected to a binary tree, but then the datastructure doesn't match the
  fundamental structure.
- **Not arbitrary height** - The tree has a global height; outside of the right
side for append, every "filled out" "subtree" is of the same size.
- **No conversion** - There is no mixing of cryptographic states.  Provides a
  clear line between the security of various algorithms, and there is no mixing,
  either intentional or unintentional of two important considerations:
  1. cryptographic digest security and 2. principal state.  However, commits may
  only appear in a subset of trees;
- **No tree Mixing** Each algorithm keeps its own independent hash tree.
- **State Mixing** Activation map is what mixes state among algs and is crypto'd
  by STH.
- **Many Trees** - One tree for each alg
- **Node hash single addressing** - A node may be addressed by one and only one
  digest algorithm.
- **No Rank** - This is good. Rank is bad and we should avoid it if we can.
- **No Prefix; pure digest** Or at least support a mode for this.
- **Opacity** - Supported, although
- **Activation Map** Signed tree heads, provides a mapping (mixing) among
  supported algs.
- **Global per-tree digest labeling** - All digests are of the same alg per
  tree.
- **Node equivalency** through activation map.
- **Leaf one-hash** Each node may have multiple hashes, they may be given
  multiple hashes after the fact.  Leafs appear to always be of one type. (Leafs
  need multi-hash support I think)
- **No digest equivalency proof**.  Equivalency Proofs are only done in
  signatures, never digests. (Concern, we have to introduce new crypto for
  equivalency)
- **Hash Equivalency through Signed Tree Head** is what imparts the equivalence
  security.  (This isn't good because it's introducing an additional class of
  cryptography, signing algs.  It would be better if the equivalence was still
  performed by hashing algorithms.)
- **No Post Facto Digest** No retroactive recalculations. (Resources) (Although
  Zami's isn't necessarily harder to implement.) CT doesn't need this, but
  everything else does.




## Synthesis: **N-ary EML (NEML)**
- **One logical Principal Tree**
- **Proofs**: Inclusion, consistency, and a new category, **cross-algorithm
  binding proofs**, aka "binding proof" using a binding root. No digital signing
  algorithms are used in the primitive.
- **Binding Root (BR)** New step to EML, is binding performed via a combined
  root.  Binding is provided through serial concat. 

  ```
  BR₀ = H₀(MR₀,MR₁)
  BR₁ = H₁(MR₁, MR₀)
  ```

  Each hashing algorithm has its own Binding root as well as a normal MR. The
  binding proof uses only digests.  The key cryptographic advantage of the NEML
  is that the security of one algorithm is never mixed with others, even within
  the BR; despite hashing another algorithm's digest, the security of the
  external digest isn't relevant with the hash's own tree. Each algorithm hash
  security is dependent only upon itself.

  The from one hashing tree to another assumes hashing algorithm security .
  Arrow then uses the BR as input for `pre`. This new design eliminates a class
  of cryptography (digital signatures) is also very good, instead of a signed
  tree head (STH, signing security which is bad)) which is excluded from NEML
  now.

**BR consistency Proof**: To prove that BR₀ is consistent with (≘) BR₁, MR₀ and
MR₁ also have to be given. Without MR₀ and MR₁, BR₀ consistency to BR₁ cannot be
proven.  Clients must have support for both hashing algorithms.

To prove bindings BR₀, BR₁ are consistent when given BR₀, BR₁, MR₀, MR₁:

```
H₀(MR₀ || MR₁) == BR₀ 
H₁(MR₀ || MR₁) == BR₁
```

Therefore, BR₀ ≘ BR₁

To prove bindings BR₀, BR₁, BR₂ are consistent when given BR₀, BR₁, BR₂, MR₀,
MR₁, MR₂:

```
H₀(MR₀ || MR₁ || MR₂) == BR₀ 
H₁(MR₀ || MR₁ || MR₂) == BR₁
H₂(MR₀ || MR₁ || MR₂) == BR₂
```

Therefore, BR₀ ≘ BR₁ ≘ BR₂

Concatenation order isn't relevant to the proof; the only consequential aspect
is that the digest of a particular hash appears in the proof.  Although the
digests in the concatenation step may appear in any order, we recommend using a
single order for all bindings. This allows for a single serialization step
followed by a O(N) hashing step.

With only a single alg, for inclusion and consistency only MR₀ is required along
with appropriate nodes.

If multiple algorithms are used, the MR and BR for each algorithm is required
followed by a binding proof.

- **Can't prove binding without Cyphr** Critically, binding roots must be
trusted.  Cyphr provides BR trust. There's no possible proofs outside of proving
given binding roots and given MR's inclusion/consistency and BR consistency.

For example, there doesn't exist a cross-algorithm binding proof that can show
that node A₀ in hash tree H₀ correlates to node A₁ in hash tree H₁.  Without
Cyphr, an attacker can provide an naive prover with arbitrary BRs.  The attacker
can spoof a dishonest BR for a dishonest MT.

NEML can't prove cross consistency without hashing the concrete object, however,
and critically, **hashing concrete/preimage values is prohibited for the proving
system**.  Only digests are provided and preimage verification is strictly
prohibited for this primitive.  After the fact a client may verify that a
resource correlates to a specific preimage, but that is outside of the scope for
MT.

- **Tradeoff: More Proofs Required, but no security mixing** Compared to a
  conversion tree, I expect more nodes are required to prove
  consistency/inclusion/binding (bad).  However, we gain the advantage that
  there's no cryptographic digest security mixing.
- **Algorithm Dropping** - If an algorithm is dropped, calculation stops at that
  point. (fantastic)  However, it might be too hard to pull this off with a BR.
- **Ordered** (Nodes are ordered as given by principal)
- **Directionality**
- **Left dense filled** No gaps in the tree (except for interior null
  boundaries)
- **Unbalanced** (The tree does not require symmetry)
- **CT Append Only**: The datastructure is only forward mutable.  Past nodes are
   immutable.  For ST, if we are using NEML, we need a mutable mode however.
   Also remember, when a resource is added in a tree that currently had it
   listed as null, that could cause a retroactive update, this should be
   supported. 
- **Mutable Mode** Support a mutation/not-append only mode for PT, ST, DT, AT,
  RT.  If we're using one datastructure for the whole of the principal, we need
  to specify that CT is append only and that other nodes are not necessarily
  required to be. 
- **Promotion**
  - Singleton promotion
  - n-ary null promotion - A tree may have a null boundary
- **N-ary** (Not binary, an inner node may have one to many children)
- **CT up is binary** from transaction root up is binary, from TR down is n-ary.
- **Arbitrary structure**  (Nodes are constructed as desired)
- **Arbitrary height** (Nodes may have one to infinite depth of children)
- **No conversion**; Binding through Combined Root
   - **Handled Mixing** through Combined Root
- **No tree Mixing** Each algorithm keeps its own independent hash tree. (Good)
- **No state mixing** Since there isn't conversion, there is no state mixing.
  The BR's have to be trusted from Cyphr. 
- **Many Hash Trees (Many "projections"); one logical tree** - Each algorithm
  has it's tree, one hash tree is projected onto another algorithm's hash tree.
- **Multi-Alg/Single-Alg Node addressing** Multiple references are supported.
  Each node must have at least one reference in a supported tree.
- **No rank** (Good)
- **No Prefix; pure digest** (Cosmically good)
- **Opacity** - Supported. There is no node that's not allowed to be opaque.
- **No signed tree heads (no STH's)** Signing is outside the scope of NEML,
  although it can provide external guidance.
- **No source of truth Activation Map**  Activation map is derived from the
  Merkle tree which is the root truth and contains all derivable information.
  The activation map is not fundamental to EML, it's metadata. 
- **Global per-tree digest labeling** - All digests are of the same alg per
  tree.  Trees are then related to another.
- **Retroactive Hashing Algorithm Addition**- If a resource, represented by a
  node, adds an algorithm, then a new root is calculated (Should be performant,
  operating in log(n) time)
- **hashing concrete/pre-image values is prohibited** The system works
  exclusively with digests.
- **All metadata is derivable from the MT**  Not height is encoded into the
  digest itself; it's proven, not a tracked external property.
- **Frontier Stack and Activation Map are derived** They are data structures
  fully derivable from the MT which is the root source of truth.