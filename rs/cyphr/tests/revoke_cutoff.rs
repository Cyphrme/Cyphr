//! One revoke-cutoff rule: `cyphr::revoke::Cutoff` answers "has this
//! revoke stopped a statement dated `now`" and "which of two cutoffs
//! stands", and `Principal::authorize` answers the same way.
//!
//! Properties:
//! - `stops(None)` (an undated statement) is always true; `stops(Some(n))` is `n >= cutoff` (SPEC
//!   6.4: the key is dead from the cutoff on).
//! - `earliest` is a lower bound that stops whatever either input stops (metamorphic: an earlier
//!   cutoff never stops less), and is commutative and idempotent.
//! - Agreement: for a key revoked at cutoff `c`, `Principal::authorize` refuses at `now` with
//!   `KeyRevoked` exactly when `Cutoff(c)` stops `Some(now)`, across a grid that straddles the
//!   boundary; and two revokes in either order leave the verdict of `earliest`.
//!
//! Red before K1: neither `Cutoff` nor `Principal::authorize` is public.
//! The frame (FIX-FRAME 2.1) gives `Cutoff(i64)`, `stops(self,
//! Option<i64>) -> bool`, `earliest(self, Cutoff) -> Cutoff`; the tuple
//! field is taken to be public so storage can build one from a stored
//! cutoff.

use cyphr::revoke::Cutoff;
use cyphr::{Error, Principal};
use proptest::prelude::*;

const T: i64 = 1_700_000_000;

proptest! {
    #[test]
    fn stops_is_the_boundary_comparison(c in any::<i64>(), n in any::<i64>()) {
        prop_assert!(Cutoff(c).stops(None));
        prop_assert_eq!(Cutoff(c).stops(Some(n)), n >= c);
    }

    /// Random pairs almost never meet at the boundary; this one lives there.
    #[test]
    fn the_boundary_itself_stops(c in any::<i32>(), d in -2i64..=2) {
        let c = i64::from(c);
        prop_assert_eq!(Cutoff(c).stops(Some(c + d)), d >= 0);
    }

    #[test]
    fn an_earlier_cutoff_never_stops_less(
        a in any::<i64>(), b in any::<i64>(), n in proptest::option::of(any::<i64>()),
    ) {
        let e = Cutoff(a).earliest(Cutoff(b));
        prop_assert_eq!(e.stops(n), Cutoff(a).stops(n) || Cutoff(b).stops(n));
        prop_assert_eq!(e.stops(n), Cutoff(b).earliest(Cutoff(a)).stops(n));
        prop_assert_eq!(e.stops(n), Cutoff(a).earliest(Cutoff(a)).stops(n) || Cutoff(b).stops(n));
    }
}

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// A principal whose genesis commit at `T` holds `key_a`.
async fn principal(pool: &test_fixtures::Pool) -> (Principal, coz::Thumbprint) {
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &[key_a.key().expect("key")],
        T,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    (p, key_a.compute_tmb().expect("tmb"))
}

#[tokio::test]
async fn authorize_agrees_with_cutoff_across_the_boundary() {
    let pool = pool();
    for c in (T - 3)..=(T + 6) {
        let (mut p, tmb) = principal(&pool).await;
        p.note_naked_revoke(&tmb, c);
        for now in T..=(T + 8) {
            let verdict = p.authorize(&tmb, now);
            if Cutoff(c).stops(Some(now)) {
                assert!(
                    matches!(verdict, Err(Error::KeyRevoked)),
                    "cutoff {c}, now {now}: want KeyRevoked, got {verdict:?}"
                );
            } else {
                assert!(verdict.is_ok(), "cutoff {c}, now {now}: {verdict:?}");
            }
        }
    }
}

#[tokio::test]
async fn the_earliest_of_two_revokes_stands_in_either_order() {
    let pool = pool();
    for (c1, c2) in [(T + 2, T + 5), (T + 5, T + 2), (T + 3, T + 3)] {
        let (mut p, tmb) = principal(&pool).await;
        p.note_naked_revoke(&tmb, c1);
        p.note_naked_revoke(&tmb, c2);
        let stand = Cutoff(c1).earliest(Cutoff(c2));
        for now in T..=(T + 8) {
            assert_eq!(
                p.authorize(&tmb, now).is_err(),
                stand.stops(Some(now)),
                "revokes {c1} then {c2}, now {now}"
            );
        }
    }
}
