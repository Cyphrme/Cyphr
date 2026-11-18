//! The certificate's parsed form and its JSON wire.
//!
//! Every byte string is base64url without padding and every family is named
//! by its Coz name. Parsing is the one way a certificate comes from outside,
//! and it refuses, before any hashing, a field over its cap (checked on the
//! encoded string before it is decoded), a list over its count, a digest not
//! the width of its family, and Principal Tree cells that are not framed:
//! every cell is a map of variants, every variant exactly its family's
//! width, every cell carrying the same families. The fold over the cells
//! concatenates their variants with no framing of its own, so the widths are
//! what keeps `[SR, CR, N]` from folding to the same root as a
//! re-partition of the same bytes.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::HashAlg;
use crate::commit_root::u64_to_hash_alg;

/// Largest decoded Principal Tree cell, leaf map and coz. An honest cell is a
/// map of at most three variants of at most 64 bytes, each as a JSON list
/// of numbers.
pub(super) const MAX_CELL: usize = 2048;
pub(super) const MAX_LEAF: usize = 2048;
pub(super) const MAX_COZ: usize = 4096;
/// Most digests in one list of siblings or peaks, and levels in one path.
const MAX_SIBLINGS: usize = 256;
const MAX_STEPS: usize = 64;
const MAX_PEAKS: usize = 64;
/// Most mutation transactions in a commit, and cozies in one transaction.
const MAX_TXS: usize = 1024;
const MAX_TX_COZIES: usize = 256;
/// Most cells of a Principal Tree: SR, CR and the nonces (SPEC 3.7.1 folds
/// at most 256 children).
const MAX_CELLS: usize = 256;

/// A digest's width in bytes.
pub(super) fn width(alg: HashAlg) -> usize {
    alg.digest_size()
}

fn alg_of_width(w: usize) -> Option<HashAlg> {
    crate::state::HASH_ALGS.into_iter().find(|&a| width(a) == w)
}

fn alg_named(name: &str) -> Result<HashAlg, String> {
    crate::state::hash_alg_named(name).map_err(|_| format!("unknown hash family {name:?}"))
}

fn encoded_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3) + 2
}

/// A byte string of at most `N` bytes, base64url on the wire.
pub(super) struct Capped<const N: usize>(pub Vec<u8>);

impl<const N: usize> Serialize for Capped<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Capped<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const N: usize>;
        impl<const N: usize> Visitor<'_> for V<N> {
            type Value = Capped<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a base64url string of at most {N} bytes")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Capped<N>, E> {
                if s.len() > encoded_len(N) {
                    return Err(E::custom(format!("a field over {N} bytes")));
                }
                Base64UrlUnpadded::decode_vec(s)
                    .map(Capped)
                    .map_err(|_| E::custom("not base64url"))
            }
        }
        d.deserialize_str(V::<N>)
    }
}

/// A list of at most `N` items, refused as it grows past that.
pub(super) struct Lim<T, const N: usize>(pub Vec<T>);

impl<T: Serialize, const N: usize> Serialize for Lim<T, N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Lim<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for V<T, N> {
            type Value = Lim<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a list of at most {N} items")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Lim<T, N>, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element()? {
                    if out.len() == N {
                        return Err(de::Error::custom(format!("a list over {N} items")));
                    }
                    out.push(item);
                }
                Ok(Lim(out))
            }
        }
        d.deserialize_seq(V::<T, N>(PhantomData))
    }
}

// ---- the validated form ----

/// The Principal Tree's cells, framed: at least SR and CR, each a map of
/// variants of exactly their family's width, every cell carrying the same
/// families.
#[derive(Clone, Debug)]
pub(super) struct Cells {
    pub raw: Vec<Vec<u8>>,
    pub families: Vec<HashAlg>,
    maps: Vec<BTreeMap<HashAlg, Vec<u8>>>,
}

impl Cells {
    pub(super) fn parse(raw: Vec<Vec<u8>>) -> Result<Self, String> {
        if !(2..=MAX_CELLS).contains(&raw.len()) {
            return Err(format!("{} principal tree cells", raw.len()));
        }
        let mut maps = Vec::with_capacity(raw.len());
        for cell in &raw {
            if cell.len() > MAX_CELL {
                return Err("a cell over its cap".into());
            }
            let m: BTreeMap<u64, Vec<u8>> =
                serde_json::from_slice(cell).map_err(|_| "a cell is not a map of variants")?;
            let mut typed = BTreeMap::new();
            for (id, bytes) in m {
                let alg = u64_to_hash_alg(id).map_err(|_| format!("unknown family {id}"))?;
                if bytes.len() != width(alg) {
                    return Err(format!("a {alg} variant of {} bytes", bytes.len()));
                }
                typed.insert(alg, bytes);
            }
            maps.push(typed);
        }
        let families: Vec<HashAlg> = maps[0].keys().copied().collect();
        if families.is_empty() || maps.iter().any(|m| !m.keys().eq(families.iter())) {
            return Err("cells that do not share their families".into());
        }
        Ok(Self {
            raw,
            families,
            maps,
        })
    }

    /// The family `alg`'s variant of cell `i`.
    pub(super) fn variant(&self, i: usize, alg: HashAlg) -> Option<&[u8]> {
        self.maps.get(i)?.get(&alg).map(Vec::as_slice)
    }
}

#[derive(Clone, Debug)]
pub(super) struct PathW {
    pub alg: HashAlg,
    pub index: u64,
    pub size: u64,
    pub steps: Vec<eml::ProofStep>,
}

#[derive(Clone, Debug)]
pub(super) struct ConsW {
    pub alg: HashAlg,
    pub proof: eml::ConsistencyProof,
}

#[derive(Clone, Debug)]
pub(super) enum Terminal {
    Path(PathW),
    Consistency(ConsW),
}

#[derive(Clone, Debug)]
pub(super) struct OpeningW {
    /// The commit's log leaf: its transaction root's variants.
    pub tr_map: Vec<u8>,
    /// The czds of each mutation transaction, in order: what the leaf's
    /// transaction root and the arrow's mutation root are both made of.
    pub txs: Vec<Vec<Vec<u8>>>,
    /// The closing coz, in its wire form.
    pub coz: Vec<u8>,
    /// The forward State Root's variants, empty when the commit leaves none.
    pub fwd: Vec<(HashAlg, Vec<u8>)>,
    /// The Principal Tree's cells at the commit before.
    pub cells: Cells,
}

#[derive(Clone, Debug)]
pub(super) struct StitchW {
    pub alg: HashAlg,
    pub leaf: PathW,
    pub opening: OpeningW,
}

/// A parsed certificate.
#[derive(Clone, Debug)]
pub(super) struct Cert {
    pub top: Cells,
    pub base: Option<Cells>,
    pub stitches: Vec<StitchW>,
    pub terminal: Terminal,
}

// ---- the raw wire ----

#[derive(Serialize, Deserialize)]
struct RawStep {
    position: usize,
    siblings: Lim<Capped<64>, MAX_SIBLINGS>,
}

#[derive(Serialize, Deserialize)]
struct RawPath {
    alg: String,
    index: u64,
    size: u64,
    steps: Lim<RawStep, MAX_STEPS>,
}

#[derive(Serialize, Deserialize)]
struct RawOpening {
    tr_map: Capped<MAX_LEAF>,
    tr_path: Lim<RawStep, MAX_TXS>,
    coz: Capped<MAX_COZ>,
    fwd_variants: Lim<(String, Capped<64>), 3>,
    pt_cells: Lim<Capped<MAX_CELL>, MAX_CELLS>,
}

#[derive(Serialize, Deserialize)]
struct RawStitch {
    alg: String,
    leaf: RawPath,
    opening: RawOpening,
}

#[derive(Serialize, Deserialize)]
struct RawEnds {
    pt_cells: Lim<Capped<MAX_CELL>, MAX_CELLS>,
}

/// The terminal object: a path (`index`, `size`, `steps`) or a consistency
/// proof (`boundary_hash`, `peak_path`, `new_peaks`, `split_index`).
#[derive(Serialize, Deserialize)]
struct RawTerminal {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    steps: Option<Lim<RawStep, MAX_STEPS>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boundary_hash: Option<Capped<64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peak_path: Option<Lim<RawStep, MAX_STEPS>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_peaks: Option<Lim<Capped<64>, MAX_PEAKS>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    split_index: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RawCert {
    top: RawEnds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base: Option<RawEnds>,
    stitches: Vec<RawStitch>,
    terminal: RawTerminal,
}

fn steps_of(raw: Vec<RawStep>, w: usize) -> Result<Vec<eml::ProofStep>, String> {
    raw.into_iter()
        .map(|s| {
            let siblings = s
                .siblings
                .0
                .into_iter()
                .map(|d| {
                    (d.0.len() == w)
                        .then_some(d.0)
                        .ok_or_else(|| format!("a digest not {w} bytes"))
                })
                .collect::<Result<_, _>>()?;
            Ok(eml::ProofStep {
                position: s.position,
                siblings,
            })
        })
        .collect()
}

fn raw_steps(steps: &[eml::ProofStep]) -> Lim<RawStep, MAX_STEPS> {
    Lim(steps
        .iter()
        .map(|s| RawStep {
            position: s.position,
            siblings: Lim(s.siblings.iter().map(|d| Capped(d.clone())).collect()),
        })
        .collect())
}

fn cells_of(raw: Lim<Capped<MAX_CELL>, MAX_CELLS>) -> Result<Cells, String> {
    Cells::parse(raw.0.into_iter().map(|c| c.0).collect())
}

fn raw_cells(c: &Cells) -> Lim<Capped<MAX_CELL>, MAX_CELLS> {
    Lim(c.raw.iter().map(|b| Capped(b.clone())).collect())
}

fn path_of(raw: RawPath) -> Result<PathW, String> {
    let alg = alg_named(&raw.alg)?;
    Ok(PathW {
        alg,
        index: raw.index,
        size: raw.size,
        steps: steps_of(raw.steps.0, width(alg))?,
    })
}

fn raw_path(p: &PathW) -> RawPath {
    RawPath {
        alg: p.alg.to_string(),
        index: p.index,
        size: p.size,
        steps: raw_steps(&p.steps),
    }
}

impl TryFrom<RawCert> for Cert {
    type Error = String;

    fn try_from(raw: RawCert) -> Result<Self, String> {
        let stitches = raw
            .stitches
            .into_iter()
            .map(|s| {
                let o = s.opening;
                let txs = o
                    .tr_path
                    .0
                    .into_iter()
                    .map(|tx| {
                        if tx.position != 0 || tx.siblings.0.is_empty() {
                            return Err("a malformed transaction".to_owned());
                        }
                        tx.siblings
                            .0
                            .into_iter()
                            .map(|c| {
                                alg_of_width(c.0.len())
                                    .map(|_| c.0)
                                    .ok_or_else(|| "a czd of no family's width".to_owned())
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if txs.iter().any(|t| t.len() > MAX_TX_COZIES) {
                    return Err("a transaction over its cozies".to_owned());
                }
                let mut fwd: Vec<(HashAlg, Vec<u8>)> = Vec::new();
                for (name, bytes) in o.fwd_variants.0 {
                    let alg = alg_named(&name)?;
                    if bytes.0.len() != width(alg) || fwd.iter().any(|(a, _)| *a == alg) {
                        return Err(format!(
                            "a {alg} forward variant of {} bytes",
                            bytes.0.len()
                        ));
                    }
                    fwd.push((alg, bytes.0));
                }
                Ok(StitchW {
                    alg: alg_named(&s.alg)?,
                    leaf: path_of(s.leaf)?,
                    opening: OpeningW {
                        tr_map: o.tr_map.0,
                        txs,
                        coz: o.coz.0,
                        fwd,
                        cells: cells_of(o.pt_cells)?,
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let t = raw.terminal;
        let alg = alg_named(&t.alg)?;
        let terminal = match (t.steps, t.peak_path) {
            (Some(steps), None) => Terminal::Path(PathW {
                alg,
                index: t.index.ok_or("a path without an index")?,
                size: t.size.ok_or("a path without a size")?,
                steps: steps_of(steps.0, width(alg))?,
            }),
            (None, Some(peak_path)) => {
                let new_peaks: Vec<Vec<u8>> = t
                    .new_peaks
                    .ok_or("a consistency proof without peaks")?
                    .0
                    .into_iter()
                    .map(|p| p.0)
                    .collect();
                let boundary_hash = t
                    .boundary_hash
                    .ok_or("a consistency proof without a boundary")?
                    .0;
                let split_index = t.split_index.ok_or("a consistency proof without a split")?;
                // Equal sizes carry no proof: all four parts empty.
                let proofless =
                    new_peaks.is_empty() && boundary_hash.is_empty() && peak_path.0.is_empty();
                if !proofless
                    && (boundary_hash.len() != width(alg)
                        || split_index >= new_peaks.len()
                        || new_peaks.iter().any(|p| p.len() != width(alg)))
                {
                    return Err("a consistency proof not framed for its family".into());
                }
                Terminal::Consistency(ConsW {
                    alg,
                    proof: eml::ConsistencyProof {
                        boundary_hash,
                        peak_path: steps_of(peak_path.0, width(alg))?,
                        new_peaks,
                        split_index,
                    },
                })
            },
            _ => return Err("a terminal that is neither a path nor a consistency proof".into()),
        };
        Ok(Cert {
            top: cells_of(raw.top.pt_cells)?,
            base: raw.base.map(|b| cells_of(b.pt_cells)).transpose()?,
            stitches,
            terminal,
        })
    }
}

fn raw_terminal(t: &Terminal) -> RawTerminal {
    match t {
        Terminal::Path(p) => RawTerminal {
            alg: p.alg.to_string(),
            index: Some(p.index),
            size: Some(p.size),
            steps: Some(raw_steps(&p.steps)),
            boundary_hash: None,
            peak_path: None,
            new_peaks: None,
            split_index: None,
        },
        Terminal::Consistency(k) => RawTerminal {
            alg: k.alg.to_string(),
            index: None,
            size: None,
            steps: None,
            boundary_hash: Some(Capped(k.proof.boundary_hash.clone())),
            peak_path: Some(raw_steps(&k.proof.peak_path)),
            new_peaks: Some(Lim(k
                .proof
                .new_peaks
                .iter()
                .map(|p| Capped(p.clone()))
                .collect())),
            split_index: Some(k.proof.split_index),
        },
    }
}

impl From<&Cert> for RawCert {
    fn from(c: &Cert) -> Self {
        let stitches = c
            .stitches
            .iter()
            .map(|s| {
                let o = &s.opening;
                RawStitch {
                    alg: s.alg.to_string(),
                    leaf: raw_path(&s.leaf),
                    opening: RawOpening {
                        tr_map: Capped(o.tr_map.clone()),
                        tr_path: Lim(o
                            .txs
                            .iter()
                            .map(|tx| RawStep {
                                position: 0,
                                siblings: Lim(tx.iter().cloned().map(Capped).collect()),
                            })
                            .collect()),
                        coz: Capped(o.coz.clone()),
                        fwd_variants: Lim(o
                            .fwd
                            .iter()
                            .map(|(a, b)| (a.to_string(), Capped(b.clone())))
                            .collect()),
                        pt_cells: raw_cells(&o.cells),
                    },
                }
            })
            .collect();
        let terminal = raw_terminal(&c.terminal);
        RawCert {
            top: RawEnds {
                pt_cells: raw_cells(&c.top),
            },
            base: c.base.as_ref().map(|b| RawEnds {
                pt_cells: raw_cells(b),
            }),
            stitches,
            terminal,
        }
    }
}

/// A path or consistency terminal as the wire's JSON object, for the
/// forger's builders in test support.
#[cfg(feature = "test-utils")]
pub(super) fn terminal_json(t: &Terminal) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(raw_terminal(t))
}
