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
