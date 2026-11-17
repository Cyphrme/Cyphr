//! Grow-only collections a commit scope shares instead of copies.
//!
//! A commit scope projects the principal's state, and a held action set,
//! a chain of commits and a set of included czds only ever grow. A
//! [`Grown`] holds what was settled behind an `Arc` and what a write added
//! beside it, so a copy of the state costs what the write adds, not what
//! the principal holds. [`Grown::settle`] folds the additions in once the
//! state is adopted, where the principal is the one holder.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A collection a [`Grown`] folds additions into.
pub trait Absorb: Default + Clone {
    /// Whether nothing is held.
    fn is_blank(&self) -> bool;
    /// Take in everything `tail` holds.
    fn absorb(&mut self, tail: Self);
}

impl<T: Clone> Absorb for Vec<T> {
    fn is_blank(&self) -> bool {
        self.is_empty()
    }

    fn absorb(&mut self, mut tail: Self) {
        self.append(&mut tail);
    }
}

impl<T: Clone + Ord> Absorb for BTreeSet<T> {
    fn is_blank(&self) -> bool {
        self.is_empty()
    }

    fn absorb(&mut self, mut tail: Self) {
        self.append(&mut tail);
    }
}

impl<K: Clone + Ord, V: Clone> Absorb for BTreeMap<K, V> {
    fn is_blank(&self) -> bool {
        self.is_empty()
    }

    fn absorb(&mut self, mut tail: Self) {
        self.append(&mut tail);
    }
}

/// A grow-only collection: the settled part, shared, and the part added
/// since. Cloning copies the additions only.
#[derive(Debug, Clone, Default)]
pub struct Grown<C: Absorb> {
    settled: Arc<C>,
    added: C,
}

impl<C: Absorb> Grown<C> {
    /// Fold the additions into the settled part. Free when the additions
    /// are none; copies the settled part only if another state shares it.
    pub fn settle(&mut self) {
        if !self.added.is_blank() {
            Arc::make_mut(&mut self.settled).absorb(std::mem::take(&mut self.added));
        }
    }
}

impl<T: Clone> Grown<Vec<T>> {
    pub fn from_vec(items: Vec<T>) -> Self {
        Self {
            settled: Arc::new(items),
            added: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.settled.len() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&mut self, item: T) {
        self.added.push(item);
    }

    pub fn last(&self) -> Option<&T> {
        self.added.last().or_else(|| self.settled.last())
    }

    /// Oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.settled.iter().chain(&self.added)
    }
}

impl<T: Clone + Ord> Grown<BTreeSet<T>> {
    pub fn contains<Q>(&self, item: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.settled.contains(item) || self.added.contains(item)
    }

    pub fn insert(&mut self, item: T) {
        if !self.settled.contains(&item) {
            self.added.insert(item);
        }
    }

    /// In no particular order: the two parts are each in order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.settled.iter().chain(&self.added)
    }
}

impl<K: Clone + Ord, V: Clone> Grown<BTreeMap<K, V>> {
    pub fn len(&self) -> usize {
        self.settled.len() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.settled.contains_key(key) || self.added.contains_key(key)
    }

    /// Hold `value` under `key` unless something is held under it: the
    /// settled part is never rewritten, so a key is held once.
    pub fn insert(&mut self, key: K, value: V) {
        if !self.settled.contains_key(&key) {
            self.added.insert(key, value);
        }
    }

    /// In key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut settled = self.settled.iter().peekable();
        let mut added = self.added.iter().peekable();
        std::iter::from_fn(move || match (settled.peek(), added.peek()) {
            (Some((a, _)), Some((b, _))) if b < a => added.next(),
            (Some(_), _) => settled.next(),
            (None, _) => added.next(),
        })
    }
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
}
