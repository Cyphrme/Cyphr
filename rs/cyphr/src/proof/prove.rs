//! The prover: it builds the certificate the verifier checks, reading what
//! it needs from the commits (their roots and Principal Tree cells) and,
//! for the paths and consistency proofs, from the log.

use super::wire::{Cells, Cert, ConsW, OpeningW, PathW, StitchW, Terminal};
use super::{Certificate, ProofError, Root};
use crate::commit_root::hash_alg_to_u64;
use crate::{Commit, HashAlg, Principal};

/// One hop of a plan: the stitch at leaf `s` in `family`'s tree of `size`
/// leaves.
struct Hop {
    family: HashAlg,
    s: u64,
    size: u64,
}

fn unprovable(what: impl Into<String>) -> ProofError {
    ProofError::Unprovable(what.into())
}

fn storage(e: impl ToString) -> ProofError {
    ProofError::Storage(e.to_string())
}

impl<S: eml::Storage> Principal<S> {
    /// The principal's root at `size` commits (the Principal Root of commit
    /// `size - 1`); `None` for 0 or a size past the log.
    #[must_use]
    pub fn root_at(&self, size: u64) -> Option<Root> {
        let commit = self.commit_at(usize::try_from(size.checked_sub(1)?).ok()?)?;
        Some(Root {
            size,
            pr: commit.pr().clone(),
        })
    }

    fn held(&self, i: u64) -> Result<&Commit, ProofError> {
        usize::try_from(i)
            .ok()
            .and_then(|i| self.commit_at(i))
            .ok_or_else(|| unprovable(format!("commit {i} is not held")))
    }

    /// The epochs of `alg`: `[start, end)` leaf ranges, `end` open as
    /// `u64::MAX`.
    fn epochs_of(&self, alg: HashAlg) -> Vec<(u64, u64)> {
        let id = hash_alg_to_u64(alg);
        self.commit_trees()
            .epochs()
            .into_iter()
            .find_map(|(i, e)| (i == id).then_some(e))
            .unwrap_or_default()
    }

    /// The start of `alg`'s epoch containing leaf `i`.
    fn epoch_start(&self, alg: HashAlg, i: u64) -> Option<u64> {
        self.epochs_of(alg)
            .into_iter()
            .find_map(|(a, e)| (a <= i && i < e).then_some(a))
    }

    /// The families a stitch at commit `s` yields: what the arrow's `pre`
    /// binds (the arrow family's variant if `PR_{s-1}` has it, else every
    /// variant).
    fn yields(&self, s: u64) -> Result<Vec<HashAlg>, ProofError> {
        let g = self
            .held(s)?
            .commit_tx()
            .0
            .last()
            .and_then(|z| z.arrow())
            .and_then(|a| a.algorithms().next())
            .ok_or_else(|| unprovable(format!("commit {s} has no arrow")))?;
        let pre = &self.held(s - 1)?.pr().0;
        Ok(if pre.contains(g) {
            vec![g]
        } else {
            pre.algorithms().collect()
        })
    }

    /// The hops from the Principal Root at `size` to a family that was
    /// active at leaf `p` (for membership; `one_epoch` asks for one epoch
    /// from `p` through the size, for consistency, which does not cross a
    /// gap), and that family and its size.
    fn plan(
        &self,
        size: u64,
        p: u64,
        one_epoch: bool,
    ) -> Result<(Vec<Hop>, HashAlg, u64), ProofError> {
        let reaches = |f: HashAlg, a: u64| {
            if one_epoch {
                a <= p
            } else {
                self.epoch_start(f, p).is_some()
            }
        };
        let start = |size: u64, families: &[HashAlg]| -> Result<(HashAlg, u64), ProofError> {
            let mut best: Option<(u64, HashAlg)> = None;
            for &f in families {
                let a = self
                    .epoch_start(f, size - 1)
                    .ok_or_else(|| unprovable(format!("{f} is not active at leaf {}", size - 1)))?;
                if reaches(f, a) {
                    return Ok((f, a));
                }
                if best.is_none_or(|(b, _)| a < b) {
                    best = Some((a, f));
                }
            }
            best.map(|(a, f)| (f, a))
                .ok_or_else(|| unprovable("no family is active"))
        };
        let mut hops = Vec::new();
        let top: Vec<HashAlg> = self.held(size - 1)?.pr().0.algorithms().collect();
        let (mut family, mut a) = start(size, &top)?;
        let mut size = size;
        loop {
            if reaches(family, a) {
                return Ok((hops, family, size));
            }
            // Stitch at the start of the family's epoch: the farthest back
            // it can go, read from the epoch timeline without looking at
            // any commit but the one stitched.
            let s = a;
            hops.push(Hop { family, s, size });
            (family, a) = start(s, &self.yields(s)?)?;
            size = s;
        }
    }

    /// The Principal Tree cells of commit `i`'s Principal Root, refusing a
    /// root with no State Root, whose cell roles the cells alone do not name.
    fn cells_of(&self, i: u64) -> Result<Cells, ProofError> {
        let commit = self.held(i)?;
        if commit.sr().is_none() {
            return Err(unprovable(format!("commit {i} left no state root")));
        }
        Cells::parse(commit.pt_cells().to_vec()).map_err(unprovable)
    }

    async fn path(&self, alg: HashAlg, index: u64, size: u64) -> Result<PathW, ProofError> {
        let proof = self
            .commit_trees()
            .inclusion_proof_at(hash_alg_to_u64(alg), index, size)
            .await
            .map_err(storage)?
            .ok_or_else(|| unprovable(format!("no {alg} path to {index} of {size}")))?;
        Ok(PathW {
            alg,
            index,
            size,
            steps: proof.path,
        })
    }

    async fn consistency(&self, alg: HashAlg, from: u64, to: u64) -> Result<ConsW, ProofError> {
        // Equal sizes carry no proof: the roots are compared.
        let proof = if from == to {
            eml::ConsistencyProof {
                boundary_hash: Vec::new(),
                peak_path: Vec::new(),
                new_peaks: Vec::new(),
                split_index: 0,
            }
        } else {
            self.commit_trees()
                .consistency_proof_between(hash_alg_to_u64(alg), from, to)
                .await
                .map_err(storage)?
                .ok_or_else(|| unprovable(format!("no {alg} consistency {from} to {to}")))?
        };
        Ok(ConsW { alg, proof })
    }

    /// Commit `s` opened for a stitch.
    fn opening_at(&self, s: u64) -> Result<OpeningW, ProofError> {
        let commit = self.held(s)?;
        let (closing_tx, mutations) = commit
            .transactions()
            .split_last()
            .ok_or_else(|| unprovable(format!("commit {s} has no transactions")))?;
        // Admission refuses every commit transaction of several cozies.
        let [closing] = closing_tx.0.as_slice() else {
            return Err(unprovable(format!(
                "commit {s}: its commit transaction has several cozies"
            )));
        };
        let algs: Vec<HashAlg> = commit.pr().0.algorithms().collect();
        let g = closing
            .arrow()
            .and_then(|a| a.algorithms().next())
            .ok_or_else(|| unprovable(format!("commit {s} has no arrow")))?;
        // The arrow family's variant first: the one the arrow binds when
        // the forward State Root has it.
        let mut fwd: Vec<(HashAlg, Vec<u8>)> = commit
            .sr()
            .map(|sr| {
                sr.0.variants()
                    .iter()
                    .map(|(&a, b)| (a, b.to_vec()))
                    .collect()
            })
            .unwrap_or_default();
        fwd.sort_by_key(|(a, _)| *a != g);
        Ok(OpeningW {
            tr_map: crate::commit_root::commit_leaf(&commit.tr().0, &algs)
                .map_err(|e| unprovable(e.to_string()))?,
            txs: mutations
                .iter()
                .map(|tx| tx.0.iter().map(|c| c.czd().as_bytes().to_vec()).collect())
                .collect(),
            coz: serde_json::to_vec(closing.raw()).map_err(|e| unprovable(e.to_string()))?,
            fwd,
            cells: self.cells_of(s - 1)?,
        })
    }

    async fn stitches(&self, hops: &[Hop]) -> Result<Vec<StitchW>, ProofError> {
        let mut out = Vec::with_capacity(hops.len());
        for hop in hops {
            out.push(StitchW {
                alg: hop.family,
                leaf: self.path(hop.family, hop.s, hop.size).await?,
                opening: self.opening_at(hop.s)?,
            });
        }
        Ok(out)
    }

    /// The certificate that commit `index` is in the log of `size`
    /// commits.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for an index or size the log lacks;
    /// [`ProofError::Storage`] when the log's store fails.
    pub async fn prove_membership(&self, index: u64, size: u64) -> Result<Certificate, ProofError> {
        if index >= size || size > self.commit_count() as u64 {
            return Err(unprovable(format!(
                "no commit {index} in a log of {size} of the {} held",
                self.commit_count()
            )));
        }
        let top = self.cells_of(size - 1)?;
        let (hops, family, cur) = self.plan(size, index, false)?;
        let stitches = self.stitches(&hops).await?;
        let terminal = Terminal::Path(self.path(family, index, cur).await?);
        Ok(Certificate(Cert {
            top,
            base: None,
            stitches,
            terminal,
        }))
    }

    /// The certificate that the log of `to` commits extends the log of
    /// `from`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for sizes the log has not passed;
    /// [`ProofError::Storage`] when the log's store fails.
    pub async fn prove_extension(&self, from: u64, to: u64) -> Result<Certificate, ProofError> {
        if from == 0 || from > to || to > self.commit_count() as u64 {
            return Err(unprovable(format!(
                "no extension from {from} to {to} in the {} commits held",
                self.commit_count()
            )));
        }
        let (base, top) = (self.cells_of(from - 1)?, self.cells_of(to - 1)?);
        let (hops, family, cur) = self.plan(to, from - 1, true)?;
        let stitches = self.stitches(&hops).await?;
        let terminal = Terminal::Consistency(self.consistency(family, from, cur).await?);
        Ok(Certificate(Cert {
            top,
            base: Some(base),
            stitches,
            terminal,
        }))
    }

    /// Test support: a path to leaf `index` in family `alg`'s tree of `size`
    /// leaves, as the wire's terminal object. It builds what a forger
    /// would too: for an index at which `alg` was inactive, the path to
    /// that position's null leaf.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] if `alg` never had a tree.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn log_path(
        &self,
        alg: HashAlg,
        index: u64,
        size: u64,
    ) -> Result<serde_json::Value, ProofError> {
        let p = self.path(alg, index, size).await?;
        super::wire::terminal_json(&Terminal::Path(p)).map_err(storage)
    }

    /// Test support: a consistency proof in family `alg`'s tree between two
    /// sizes, as the wire's terminal object, including sizes at which
    /// `alg` had no tree yet (nulls), as a forger would build.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`].
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn family_consistency(
        &self,
        alg: HashAlg,
        from: u64,
        to: u64,
    ) -> Result<serde_json::Value, ProofError> {
        let c = self.consistency(alg, from, to).await?;
        super::wire::terminal_json(&Terminal::Consistency(c)).map_err(storage)
    }
}
