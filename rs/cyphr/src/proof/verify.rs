//! The verifier: every proof is `PR` -(open)-> `CR` -(hop)*-> terminal.
//!
//! `PR[X]` binds `CR[X]` alone (each family's hasher reads only its own
//! variant of a cell), so an opening yields only the families the hash that
//! reached it binds: all of a pinned Principal Root's, at the ends; at a
//! stitch, what the arrow's `pre` binds under the conversion rule.

use super::wire::{Cells, Cert, ConsW, OpeningW, PathW, StitchW, Terminal, width};
use super::{Anchor, Cause as ProofError, Certificate, Root};
use crate::commit_root::{MaltHasher, hash_alg_to_u64};
use crate::multihash::MultihashDigest;
use crate::state::{TaggedCzd, TaggedDigest, hash_concat_bytes, hash_sorted_concat_bytes};
use crate::{HashAlg, PrincipalRoot, TransactionRoot};

/// Family roots of the log at one size.
pub(super) type Roots = Vec<(HashAlg, Vec<u8>)>;

fn mismatch(what: impl Into<String>) -> ProofError {
    ProofError::Mismatch(what.into())
}

fn asked(what: impl Into<String>) -> ProofError {
    ProofError::Asked(what.into())
}

fn framing(what: impl Into<String>) -> ProofError {
    ProofError::Framing(what.into())
}

/// STUB. The transaction root of the commit `bundle` carries, under family
/// `alg` alone (all a walk in `alg` needs): each transaction's cozies'
/// czds converted to `alg`, grouped as the transactions group them, the
/// commit transaction last. A bundle suffices; the family set the commit
/// was stored with is not needed.
fn tr_of_bundle(
    _bundle: &crate::replay::WireBundle,
    _alg: HashAlg,
) -> Result<TransactionRoot, ProofError> {
    unimplemented!("stub: tr_of_bundle")
}

fn root_of(roots: &Roots, alg: HashAlg) -> Result<&[u8], ProofError> {
    roots
        .iter()
        .find_map(|(a, r)| (*a == alg).then_some(r.as_slice()))
        .ok_or(ProofError::Family)
}

/// The Principal Tree root over `cells` in family `alg`.
fn fold(cells: &Cells, alg: HashAlg) -> Result<Vec<u8>, ProofError> {
    crate::principal_tree::fold_cells(alg, &cells.raw).map_err(|_| ProofError::PtCell)
}

/// The Commit Root's variants as the cells hold them: the families `of`
/// asks for.
pub(super) fn cr_roots(cells: &Cells, of: &[HashAlg]) -> Result<Roots, ProofError> {
    of.iter()
        .map(|&a| {
            cells
                .variant(1, a)
                .map(|d| (a, d.to_vec()))
                .ok_or(ProofError::PtCell)
        })
        .collect()
}

/// Open a Principal Root that is pinned (the anchor's, or the head a
/// peer claims): the cells carry exactly its families, each folds to its
/// variant, and the Commit Root's every variant is then bound.
pub(super) fn open_pinned(cells: &Cells, pr: &PrincipalRoot) -> Result<Roots, ProofError> {
    if !pr.0.algorithms().eq(cells.families.iter().copied()) {
        return Err(ProofError::PtCell);
    }
    for (&alg, bound) in pr.0.variants() {
        if fold(cells, alg)? != **bound {
            return Err(ProofError::PtCell);
        }
    }
    cr_roots(cells, &cells.families)
}

fn digest_leaf(hasher: &MaltHasher) -> Vec<u8> {
    use eml::Hasher as _;
    // A leaf with no variant for the family: its null constant.
    hasher.leaf(&[])
}

/// Whether `leaf` sits at `index` of the family tree of `size` leaves under
/// `root`.
fn reaches(alg: HashAlg, leaf: &[u8], p: &PathW, root: &[u8]) -> bool {
    crate::commit_root::verify_inclusion(
        &MaltHasher::new(alg),
        leaf,
        p.index,
        p.size,
        &eml::InclusionProof {
            path: p.steps.clone(),
        },
        root,
    )
}

/// What the arrow's `pre` binds, from the variants of `PR_{s-1}` the cells
/// give, under Cyphr's component conversion rule: the arrow family's variant
/// if the Principal Root has it (that family alone is bound), else the one
/// variant, else the hash of them all (every family is bound).
fn derive_pre(cells: &Cells, g: HashAlg) -> Result<(Vec<u8>, Vec<HashAlg>), ProofError> {
    if cells.families.contains(&g) {
        return Ok((fold(cells, g)?, vec![g]));
    }
    let mut folds = Vec::with_capacity(cells.families.len());
    for &x in &cells.families {
        folds.push(fold(cells, x)?);
    }
    if let [only] = folds.as_slice() {
        return Ok((only.clone(), cells.families.clone()));
    }
    let all: Vec<&[u8]> = folds.iter().map(Vec::as_slice).collect();
    Ok((hash_sorted_concat_bytes(g, &all), cells.families.clone()))
}

fn convert(czd: &[u8], to: HashAlg) -> Result<Vec<u8>, ProofError> {
    let from = crate::state::HASH_ALGS
        .into_iter()
        .find(|&a| width(a) == czd.len())
        .ok_or(ProofError::Arrow)?;
    let czd = coz::Czd::from_bytes(czd.to_vec());
    Ok(TaggedCzd::new(&czd, from).convert_to(to))
}

/// A transaction's id in family `alg` (SPEC 3.7.5): a lone coz's czd
/// promoted, else the hash of the czds in order.
fn tx_id(czds: &[Vec<u8>], alg: HashAlg) -> Result<Vec<u8>, ProofError> {
    let converted: Vec<Vec<u8>> = czds
        .iter()
        .map(|c| convert(c, alg))
        .collect::<Result<_, _>>()?;
    if let [one] = converted.as_slice() {
        return Ok(one.clone());
    }
    let refs: Vec<&[u8]> = converted.iter().map(Vec::as_slice).collect();
    Ok(hash_concat_bytes(alg, &refs))
}

/// Cross one epoch boundary: leaf `s` (whose family-`f` variant is `leaf`)
/// opened through its transaction root and its closing coz to the arrow,
/// and the arrow to `PR_{s-1}` and the Commit Root it holds.
fn open_stitch(f: HashAlg, leaf: &[u8], o: &OpeningW) -> Result<(Roots, HashAlg), ProofError> {
    let coz = crate::replay::StoredCoz::from_wire(&o.coz).map_err(|_| ProofError::Arrow)?;
    let arrow: TaggedDigest = coz
        .pay()
        .get("arrow")
        .and_then(serde_json::Value::as_str)
        .and_then(|a| a.parse().ok())
        .ok_or(ProofError::Arrow)?;
    let g = arrow.alg();

    // The leaf binds the transaction ids, and so the czds, of the commit.
    let closing = TaggedCzd::new(coz.czd(), coz.hash_alg()).convert_to(f);
    let mut parts: Vec<Vec<u8>> = o
        .txs
        .iter()
        .map(|tx| tx_id(tx, f))
        .collect::<Result<_, _>>()?;
    if parts.is_empty() {
        return Err(ProofError::Arrow);
    }
    parts.push(closing);
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    if hash_concat_bytes(f, &refs) != leaf {
        return Err(ProofError::Arrow);
    }

    // The arrow: pre, fwd (when the commit leaves one), TMR, in SPEC 4.2
    // order. TMR is recomputed from those czds, never carried.
    let (pre, yields) = derive_pre(&o.cells, g)?;
    let tmr_ids: Vec<Vec<u8>> = o
        .txs
        .iter()
        .map(|tx| tx_id(tx, g))
        .collect::<Result<_, _>>()?;
    let tmr = match tmr_ids.as_slice() {
        [one] => one.clone(),
        many => {
            let refs: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
            hash_concat_bytes(g, &refs)
        },
    };
    let fwd = if o.fwd.is_empty() {
        None
    } else {
        let md = MultihashDigest::new(
            o.fwd
                .iter()
                .map(|(a, b)| (*a, b.clone().into_boxed_slice()))
                .collect(),
        )
        .map_err(|_| ProofError::Arrow)?;
        Some(
            md.arrow_component_bytes(g)
                .map_err(|_| ProofError::Arrow)?
                .into_owned(),
        )
    };
    let mut components: Vec<&[u8]> = vec![&pre];
    components.extend(fwd.as_deref());
    components.push(&tmr);
    if hash_concat_bytes(g, &components) != arrow.as_bytes() {
        return Err(ProofError::Arrow);
    }
    Ok((cr_roots(&o.cells, &yields)?, g))
}

/// Cross every stitch from `roots` at `size`: the roots and size reached.
fn walk(mut roots: Roots, mut size: u64, stitches: &[StitchW]) -> Result<(Roots, u64), ProofError> {
    for st in stitches {
        let root = root_of(&roots, st.alg)?;
        let (leaf, o) = (&st.leaf, &st.opening);
        if leaf.alg != st.alg || leaf.size != size || leaf.index == 0 || leaf.index >= size {
            return Err(mismatch(format!(
                "a stitch at {} of {} in a log of {size}",
                leaf.index, leaf.size
            )));
        }
        let map: std::collections::BTreeMap<u64, Vec<u8>> =
            serde_json::from_slice(&o.tr_map).map_err(|_| framing("a leaf that is no map"))?;
        let digest = map
            .get(&hash_alg_to_u64(st.alg))
            .filter(|d| d.len() == width(st.alg))
            .ok_or(ProofError::Path)?;
        if !reaches(st.alg, digest, leaf, root) {
            return Err(ProofError::Path);
        }
        let (next, _) = open_stitch(st.alg, digest, o)?;
        roots = next;
        size = leaf.index;
    }
    Ok((roots, size))
}

fn parse(c: &Certificate) -> &Cert {
    &c.0
}

pub(super) fn membership(
    anchor: &Anchor<'_>,
    certificate: &Certificate,
    size: u64,
    index: u64,
    bundle: &crate::replay::WireBundle,
) -> Result<(), ProofError> {
    let cert = parse(certificate);
    let Terminal::Path(path) = &cert.terminal else {
        return Err(framing("a membership claim needs a path"));
    };
    if cert.base.is_some() {
        return Err(framing("not a certificate of membership"));
    }
    if index >= size {
        return Err(asked(format!("index {index} is not below the size {size}")));
    }
    let pr = anchor
        .pr_at(size)
        .ok_or_else(|| asked(format!("the anchor pins no root at size {size}")))?;
    let (roots, cur) = walk(open_pinned(&cert.top, pr)?, size, &cert.stitches)?;
    let root = root_of(&roots, path.alg)?;
    if path.size != cur || path.index != index {
        return Err(mismatch(format!(
            "a path to {} of {}, not {index} of {cur}",
            path.index, path.size
        )));
    }
    // A holder of the chain reads the leaf from it: the path must reach
    // the root, and the claim must be the commit it holds there. A thin
    // client has only the claim.
    let tr = tr_of_bundle(bundle, path.alg)?;
    let own = anchor.tr_at(index);
    let leaf = own.unwrap_or(&tr).get(path.alg);
    let null;
    let reached = reaches(
        path.alg,
        match leaf {
            Some(l) => l,
            None => {
                null = digest_leaf(&MaltHasher::new(path.alg));
                &null
            },
        },
        path,
        root,
    );
    if !reached {
        return Err(if own.is_some() {
            ProofError::Path
        } else {
            mismatch("the transaction root is not the leaf at that index")
        });
    }
    if leaf.is_none() {
        // The family had no leaf there: the path is to a null.
        return Err(ProofError::Path);
    }
    if own.is_some_and(|own| own.get(path.alg) != tr.get(path.alg)) {
        return Err(mismatch("not the transaction root of that commit"));
    }
    Ok(())
}

pub(super) fn extension(
    anchor: &Anchor<'_>,
    certificate: &Certificate,
    from: u64,
    head: &Root,
) -> Result<(), ProofError> {
    let cert = parse(certificate);
    let (Terminal::Consistency(ConsW { alg, proof }), Some(base)) = (&cert.terminal, &cert.base)
    else {
        return Err(framing("an extension claim needs a base and a consistency"));
    };
    if from == 0 || head.size < from {
        return Err(asked(format!(
            "a head of {} does not follow {from}",
            head.size
        )));
    }
    let old = anchor.old_roots(from, base)?;
    let (roots, cur) = walk(open_pinned(&cert.top, &head.pr)?, head.size, &cert.stitches)?;
    let (old, new) = (root_of(&old, *alg)?, root_of(&roots, *alg)?);
    let holds = match from.cmp(&cur) {
        std::cmp::Ordering::Greater => false,
        // Equal sizes carry no proof: the logs agree exactly when the roots do.
        std::cmp::Ordering::Equal => old == new,
        std::cmp::Ordering::Less => crate::commit_root::verify_consistency(
            &MaltHasher::new(*alg),
            from,
            cur,
            proof,
            old,
            new,
        ),
    };
    if holds {
        Ok(())
    } else {
        Err(ProofError::NotAnExtension)
    }
}
