//! Grow-only collections a commit scope shares instead of copies.
//!
//! A commit scope projects the principal's state, and a held action set,
//! a chain of commits and a set of included czds only ever grow. A
//! [`Grown`] holds what was settled as shared segments and what a write
//! added beside them, so a copy of the state costs what the write adds, not
//! what the principal holds. [`Grown::settle`] takes the additions in once
//! the state is adopted. It never copies a shared segment: it folds into
//! the last segment when nothing else holds it, and otherwise starts a new
//! one, which a fork or detach of the principal leaves for the next write
//! to extend.

use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::iter::Peekable;
use std::sync::Arc;

/// A collection a [`Grown`] folds additions into.
pub trait Absorb: Default + Clone {
    /// How many items are held.
    fn weight(&self) -> usize;
    /// Take in everything `tail` holds.
    fn absorb(&mut self, tail: Self);

    /// Whether nothing is held.
    fn is_blank(&self) -> bool {
        self.weight() == 0
    }
}

impl<T: Clone> Absorb for Vec<T> {
    fn weight(&self) -> usize {
        self.len()
    }

    fn absorb(&mut self, mut tail: Self) {
        self.append(&mut tail);
    }
}

// Sets and maps extend item by item: O(tail log held), where `append` would
// walk what is held too.
impl<T: Clone + Ord> Absorb for BTreeSet<T> {
    fn weight(&self) -> usize {
        self.len()
    }

    fn absorb(&mut self, tail: Self) {
        self.extend(tail);
    }
}

impl<K: Clone + Ord, V: Clone> Absorb for BTreeMap<K, V> {
    fn weight(&self) -> usize {
        self.len()
    }

    fn absorb(&mut self, tail: Self) {
        self.extend(tail);
    }
}

/// A grow-only collection: the settled segments, shared, and the part added
/// since. Cloning copies the additions and one pointer per segment.
///
/// Segments are in order, and a key of a map or set is held in one at most.
///
/// # Segment bound
///
/// Segments are size-tiered: after every [`Self::settle`], each segment
/// weighs more than twice the one after it. Settle pushes the additions as
/// a segment, then while `2 * newest >= previous` merges the newest into
/// the previous (by move if nothing else holds them, else by copying).
///
/// - Count: with `S` segments the oldest weighs more than `2^(S-1)` times the newest, which weighs
///   at least 1, so `n > 2^(S-1)` and `S <= log2(n) + 1`, whoever else shares the segments. A point
///   read pays that factor, a range read an S-way merge.
/// - Copy: a merge copies at most the previous and the newest segment, and `previous <= 2 *
///   newest`, so it copies at most `3 * newest` items. The merged segment weighs at least `1.5 *
///   newest` and at least `1.5 * previous`, so an item sits in a merge input at most `log_{1.5}(n)`
///   times, and `n` items cost `O(n log n)` copies in all: O(log n) each, amortised, and never a
///   copy of a segment much larger than what the write added (the forked history is the oldest,
///   largest segment, which no small write reaches).
#[derive(Debug, Clone)]
pub struct Grown<C: Absorb> {
    settled: Vec<Arc<C>>,
    added: C,
}

impl<C: Absorb> Default for Grown<C> {
    fn default() -> Self {
        Self {
            settled: Vec::new(),
            added: C::default(),
        }
    }
}

impl<C: Absorb> Grown<C> {
    /// Take the additions into the settled segments, keeping the segments
    /// within the bound above.
    pub fn settle(&mut self) {
        if self.added.is_blank() {
            return;
        }
        self.settled.push(Arc::new(std::mem::take(&mut self.added)));
        while self.settled.len() >= 2 {
            let n = self.settled.len();
            if 2 * self.settled[n - 1].weight() < self.settled[n - 2].weight() {
                return;
            }
            let Some(newest) = self.settled.pop() else {
                return;
            };
            let tail = Arc::try_unwrap(newest).unwrap_or_else(|shared| (*shared).clone());
            if let Some(previous) = self.settled.last_mut() {
                Arc::make_mut(previous).absorb(tail);
            }
        }
    }

    /// How many settled segments are held.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn segments(&self) -> usize {
        self.settled.len()
    }
}

impl<T: Clone> Grown<Vec<T>> {
    pub fn from_vec(items: Vec<T>) -> Self {
        Self {
            settled: vec![Arc::new(items)],
            added: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.settled.iter().map(|s| s.len()).sum::<usize>() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&mut self, item: T) {
        self.added.push(item);
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        let mut rest = index;
        for segment in &self.settled {
            if rest < segment.len() {
                return segment.get(rest);
            }
            rest -= segment.len();
        }
        self.added.get(rest)
    }

    pub fn last(&self) -> Option<&T> {
        self.added
            .last()
            .or_else(|| self.settled.iter().rev().find_map(|s| s.last()))
    }

    /// Oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.settled
            .iter()
            .flat_map(|s| s.iter())
            .chain(&self.added)
    }
}

impl<T: Clone + Ord> Grown<BTreeSet<T>> {
    pub fn contains<Q>(&self, item: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.added.contains(item) || self.settled.iter().any(|s| s.contains(item))
    }

    pub fn insert(&mut self, item: T) {
        if !self.settled.iter().any(|s| s.contains(&item)) {
            self.added.insert(item);
        }
    }

    /// In no particular order: the parts are each in order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.settled
            .iter()
            .flat_map(|s| s.iter())
            .chain(&self.added)
    }
}

impl<K: Clone + Ord, V: Clone> Grown<BTreeMap<K, V>> {
    pub fn len(&self) -> usize {
        self.settled.iter().map(|s| s.len()).sum::<usize>() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.added.contains_key(key) || self.settled.iter().any(|s| s.contains_key(key))
    }

    /// Hold `value` under `key` unless something is held under it: a
    /// settled segment is never rewritten, so a key is held once.
    pub fn insert(&mut self, key: K, value: V) {
        if !self.settled.iter().any(|s| s.contains_key(&key)) {
            self.added.insert(key, value);
        }
    }

    /// In key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        merged(self.runs(|m| m.range::<K, _>(..)))
    }

    /// In key order, from `from` on.
    pub fn iter_from(&self, from: &K) -> impl Iterator<Item = (&K, &V)> {
        merged(self.runs(|m| m.range(from..)))
    }

    fn runs<'a>(
        &'a self,
        run: impl Fn(&'a BTreeMap<K, V>) -> btree_map::Range<'a, K, V>,
    ) -> Vec<Peekable<btree_map::Range<'a, K, V>>> {
        self.settled
            .iter()
            .map(|s| run(s))
            .chain(std::iter::once(run(&self.added)))
            .map(Iterator::peekable)
            .collect()
    }
}

/// Ascending runs of disjoint keys, as one.
fn merged<'a, K: Ord + 'a, V: 'a>(
    mut runs: Vec<Peekable<btree_map::Range<'a, K, V>>>,
) -> impl Iterator<Item = (&'a K, &'a V)> {
    std::iter::from_fn(move || {
        let mut least: Option<(usize, &'a K)> = None;
        for (i, run) in runs.iter_mut().enumerate() {
            if let Some(&(k, _)) = run.peek()
                && least.is_none_or(|(_, best)| k < best)
            {
                least = Some((i, k));
            }
        }
        least.and_then(|(i, _)| runs[i].next())
    })
}

// Unit tests: a `Grown` is a cost structure whose reads must not depend on
// how its content is split between the settled and the added part, and no
// scenario can observe the split.
#[cfg(test)]
mod tests {
    use super::*;

    /// Reads answer the same before and after the additions settle, and
    /// what was settled is kept by the next settle.
    #[test]
    fn a_vec_reads_the_same_whether_or_not_it_is_settled() {
        let mut v = Grown::from_vec(vec![1, 2]);
        v.push(3);
        let before: Vec<_> = v.iter().copied().collect();
        assert_eq!((v.len(), v.is_empty()), (3, false));
        assert!(Grown::<Vec<u8>>::default().is_empty());
        v.settle();
        v.push(4);
        v.settle();
        assert_eq!(before, [1, 2, 3]);
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!((v.len(), v.last()), (4, Some(&4)));
        assert_eq!((v.get(1), v.get(3), v.get(4)), (Some(&2), Some(&4), None));
    }

    #[test]
    fn a_set_holds_every_member_whether_or_not_it_is_settled() {
        let mut s = Grown::<BTreeSet<u8>>::default();
        s.insert(1);
        s.settle();
        s.insert(2);
        assert!(s.contains(&1) && s.contains(&2));
        assert_eq!(s.iter().count(), 2);
        s.settle();
        assert!(s.contains(&1) && s.contains(&2) && !s.contains(&3));
    }

    /// A map reads in key order across both parts, holds a key once, and
    /// keeps what it settled.
    #[test]
    fn a_map_reads_in_key_order_across_both_parts() {
        let mut m = Grown::<BTreeMap<u8, char>>::default();
        m.insert(2, 'b');
        m.insert(4, 'd');
        m.settle();
        m.insert(1, 'a');
        m.insert(3, 'c');
        m.insert(2, 'x');
        let read =
            |m: &Grown<BTreeMap<u8, char>>| m.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>();
        let expected = [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')];
        assert_eq!(read(&m), expected);
        assert_eq!(m.iter_from(&3).map(|(k, _)| *k).collect::<Vec<_>>(), [3, 4]);
        assert_eq!((m.len(), m.is_empty()), (4, false));
        assert!(m.contains_key(&1) && m.contains_key(&4) && !m.contains_key(&5));
        assert!(Grown::<BTreeMap<u8, u8>>::default().is_empty());
        m.settle();
        assert_eq!(read(&m), expected);
        assert_eq!(m.len(), 4);
    }

    /// A copy shares the settled part: settling the copy leaves the
    /// original as it was.
    #[test]
    fn settling_a_copy_leaves_the_original_alone() {
        let mut original = Grown::from_vec(vec![1]);
        let mut copy = original.clone();
        copy.push(2);
        copy.settle();
        assert_eq!(original.iter().count(), 1);
        original.push(9);
        assert_eq!(copy.iter().copied().collect::<Vec<_>>(), [1, 2]);
    }

    thread_local! {
        static CLONES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// An item that counts its clones, to see a segment copied.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Counted(u8);

    impl Clone for Counted {
        fn clone(&self) -> Self {
            CLONES.with(|c| c.set(c.get() + 1));
            Self(self.0)
        }
    }

    /// Settling a copy of each collection kind with a small write copies no
    /// held item, and reads cover the segments the copy left. A count is the
    /// one evaluator for a copy that no read can tell from a share.
    #[test]
    fn settling_a_shared_part_copies_nothing_and_reads_across_segments() {
        let v = Grown::from_vec((1..=6).map(Counted).collect());
        let mut s = Grown::<BTreeSet<Counted>>::default();
        let mut m = Grown::<BTreeMap<u8, Counted>>::default();
        for n in (10..=15).step_by(1) {
            s.insert(Counted(n));
        }
        for k in [2, 4, 6, 8, 10, 12] {
            m.insert(k, Counted(k));
        }
        s.settle();
        m.settle();
        let (mut v2, mut s2, mut m2) = (v.clone(), s.clone(), m.clone());
        let before = CLONES.with(|c| c.get());
        v2.push(Counted(7));
        s2.insert(Counted(1));
        m2.insert(3, Counted(3));
        m2.insert(1, Counted(1));
        m2.insert(2, Counted(99));
        v2.settle();
        s2.settle();
        m2.settle();
        assert_eq!(CLONES.with(|c| c.get()) - before, 0);
        assert_eq!(
            v2.iter().map(|c| c.0).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            (v2.get(6).map(|c| c.0), v2.last().map(|c| c.0)),
            (Some(7), Some(7))
        );
        assert_eq!((v2.get(1).map(|c| c.0), v2.get(7)), (Some(2), None));
        assert!(s2.contains(&Counted(1)) && s2.contains(&Counted(15)));
        assert_eq!(s2.iter().count(), 7);
        assert_eq!(
            m2.iter().map(|(k, c)| (*k, c.0)).collect::<Vec<_>>(),
            [
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (6, 6),
                (8, 8),
                (10, 10),
                (12, 12)
            ]
        );
        assert_eq!(
            m2.iter_from(&8).map(|(k, _)| *k).collect::<Vec<_>>(),
            [8, 10, 12]
        );
        assert_eq!(m2.len(), 8);
        // The original is untouched.
        assert_eq!((v.len(), s.iter().count(), m.len()), (6, 6, 6));
    }

    /// Whoever holds a copy, N one-item settles leave at most log2(N) + 1
    /// segments and copy O(N log N) items in all (the bound proved on
    /// [`Grown`]); no read sees the segments, so only a count can pin it.
    #[test]
    fn segments_stay_logarithmic_and_copies_amortised_while_a_copy_is_held() {
        for held in [false, true] {
            let mut g = Grown::from_vec(vec![Counted(0)]);
            let mut copies_held = Vec::new();
            let before = CLONES.with(|c| c.get());
            let mut widest = 0;
            for n in 1..=600u32 {
                g.push(Counted(0));
                g.settle();
                if held && n % 50 == 0 {
                    copies_held.push(g.clone());
                }
                widest = widest.max(g.segments());
                let bound = f64::from(n + 1).log2() as usize + 1;
                assert!(g.segments() <= bound, "n={n}: {} segments", g.segments());
            }
            let copies = CLONES.with(|c| c.get()) - before;
            // 601 items, log_{1.5}(601) = 16: 3 copies per merge input is slack.
            assert!(copies <= 601 * 16 * 3, "held={held}: {copies} copies");
            assert_eq!(g.len(), 601);
            assert!(widest <= 10);
            assert_eq!(copies_held.len(), if held { 12 } else { 0 });
        }
    }
}
