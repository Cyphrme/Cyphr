//! One canonical form: `cyphr::replay::canonicalize` sorts every object's
//! keys at every depth, and is public so the storage engine's
//! `canonicalize_value` (`import.rs`) has something to call.
//!
//! Properties over arbitrary JSON: idempotent; the result does not depend
//! on the key order the input arrived in (metamorphic: reversing every
//! object's key order first changes nothing); every object in the result
//! is in key order; arrays keep their element order.
//!
//! Red before K1: `canonicalize` is private to `replay`.

use cyphr::replay::canonicalize;
use proptest::prelude::*;
use serde_json::{Map, Value};

fn json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i32>().prop_map(Value::from),
        "[a-z]{0,6}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z]{1,4}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// `v` with every object's keys inserted in reverse order.
fn reversed(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m.iter().rev() {
                out.insert(k.clone(), reversed(x));
            }
            Value::Object(out)
        },
        Value::Array(a) => Value::Array(a.iter().map(reversed).collect()),
        other => other.clone(),
    }
}

fn canonical(mut v: Value) -> String {
    canonicalize(&mut v);
    serde_json::to_string(&v).expect("serialize")
}

fn keys_sorted(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            let keys: Vec<&String> = m.keys().collect();
            keys.windows(2).all(|w| w[0] <= w[1]) && m.values().all(keys_sorted)
        },
        Value::Array(a) => a.iter().all(keys_sorted),
        _ => true,
    }
}

proptest! {
    #[test]
    fn canonical_form_is_independent_of_key_order(v in json()) {
        prop_assert_eq!(canonical(v.clone()), canonical(reversed(&v)));
    }

    #[test]
    fn canonical_form_is_idempotent_and_sorted(v in json()) {
        let mut once = v;
        canonicalize(&mut once);
        prop_assert!(keys_sorted(&once));
        let text = serde_json::to_string(&once).expect("serialize");
        prop_assert_eq!(canonical(once), text);
    }

    #[test]
    fn arrays_keep_their_order(items in proptest::collection::vec(any::<i32>(), 0..8)) {
        let mut v = Value::Array(items.iter().copied().map(Value::from).collect());
        canonicalize(&mut v);
        let want: Vec<Value> = items.into_iter().map(Value::from).collect();
        prop_assert_eq!(v, Value::Array(want));
    }
}
