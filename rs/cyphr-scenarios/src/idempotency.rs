//! The Idempotency probe: SPEC 7.6 observed on a running peer.
//!
//! "For transactions, coz reuse by a particular principal is prohibited and
//! results in error `COZ_REUSE`." The observation pushes a principal whose
//! key `golden` creates `key_a` (coz D, commit 0) and deletes it (commit 1),
//! so D is state-valid again, then pushes a commit that re-includes D
//! verbatim. A peer that has the capability refuses it with a client error
//! naming `COZ_REUSE` and keeps its tip; a peer without it accepts it.
//!
//! The replay commit cannot be built through the core, which now refuses
//! reuse, so it is the recorded bundle `cyphr-server/tests/coz_reuse.rs`
//! pins (same recipe: pool keys, `now = T`, deterministic ES256 signatures).
//! Commits 0 and 1 are rebuilt here from the same two pool keys
//! (`tests/keys/pool.toml`, copied below because the recording is bound to
//! them); that the recording still re-includes commit 0's D is checked
//! before anything is pushed.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr::signer::SoftwareSigner;
use serde_json::{Value, json};

use crate::bins::Bins;
use crate::peer::{Limits, Peer, Role};

const T: i64 = 1_700_000_000;

/// `tests/keys/pool.toml` `golden` and `key_a` (ES256): `(prv, pub)`.
const GOLDEN: (&str, &str) = (
    "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
    "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
);
const KEY_A: (&str, &str) = (
    "diAOt9EWEjvRMhi8b16ZNeHQJtsCO2z3Sjv6gwslIpY",
    "LgM8w00BEbGdNlbugzQYDaMuvq9PsJpY3bK8B9yTsxy01JwSKIt84A6whEx8ZVqtAoqQ1xrPAzFwPPbfecN_vQ",
);

/// `cyphr-server/tests/coz_reuse.rs` `REPLAY_BLOBS`: `[D, commit/create]`.
const REPLAY_BLOBS: [&str; 2] = [
    "eyJwYXkiOnsiYWxnIjoiRVMyNTYiLCJpZCI6InhnSnU4R3NFR09WWkNqYlZVWG5fRDRnczRhdWxpZlktVlFHMkZNbEphSEUiLCJub3ciOjE3MDAwMDAwMDAsInRtYiI6IlU1WFVab3RzLVdtUVljUVdtc083NTFYazB5ZVZpOVhVS1dRMm1HejZBcWciLCJ0eXAiOiJjeXBoci5tZS9jeXBoci9rZXkvY3JlYXRlIn0sInNpZyI6InpFRUl1TURNM2E2R2VxZkFhc2hMM1dpeFNidS1MRmUxc0JzSEw5Tzk4MFpyRjVzQ0ttaXJuS2VhVDlpbmZzSEVKc1RCeDFjYUtLV1g3NVl3WThZRUp3Iiwia2V5Ijp7ImFsZyI6IkVTMjU2IiwicHViIjoiTGdNOHcwMEJFYkdkTmxidWd6UVlEYU11dnE5UHNKcFkzYks4Qjl5VHN4eTAxSndTS0l0ODRBNndoRXg4WlZxdEFvcVExeHJQQXpGd1BQYmZlY05fdlEiLCJ0bWIiOiJ4Z0p1OEdzRUdPVlpDamJWVVhuX0Q0Z3M0YXVsaWZZLVZRRzJGTWxKYUhFIn19",
    "eyJwYXkiOnsiYWxnIjoiRVMyNTYiLCJhcnJvdyI6IlNIQS0yNTY6M3p0LVprb2hvSWtBczZPM0RWNzNKSUcwVzhJVkxRcDdBeEpRS3daUmg2NCIsIm5vdyI6MTcwMDAwMDAwMCwidG1iIjoiVTVYVVpvdHMtV21RWWNRV21zTzc1MVhrMHllVmk5WFVLV1EybUd6NkFxZyIsInR5cCI6ImN5cGhyLm1lL2N5cGhyL2NvbW1pdC9jcmVhdGUifSwic2lnIjoiR2l2WDlGLUJtdDNTWkR4X0NEdElIbkktbzhOWWNWdnMwRnhiR1pNZGZmWkVZdU50Z0JLVkJKajhRYzVsbHA5NzhpOHVUM00ydkVCem8tQmRtZkF6RncifQ",
];

/// What a fresh peer answered to the replay.
#[derive(Debug)]
pub struct ReplayAnswer {
    pub status: u16,
    /// The refusal message, lowercased (empty when none).
    pub error: String,
    /// The principal's commit count before and after the replay.
    pub count_before: u64,
    pub count_after: u64,
}

impl ReplayAnswer {
    /// The SPEC 7.6 outcome: a typed client error naming `COZ_REUSE`, and
    /// the chain unchanged.
    pub fn refused_as_reuse(&self) -> bool {
        (self.status == 409 || self.status == 422)
            && (self.error.contains("coz_reuse") || self.error.contains("coz reuse"))
            && self.count_after == self.count_before
    }
}

struct PoolSigner {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn pool_key((prv, pubk): (&str, &str)) -> Result<PoolSigner, String> {
    let b64 = |s: &str| Base64UrlUnpadded::decode_vec(s).map_err(|e| e.to_string());
    let alg = coz::Alg::from_str("ES256").ok_or("no ES256")?;
    let pubb = b64(pubk)?;
    Ok(PoolSigner {
        alg: alg.name().to_owned(),
        prv: b64(prv)?,
        tmb: alg.compute_thumbprint(&pubb).ok_or("no thumbprint")?,
        pubb,
    })
}

fn key_of(k: &PoolSigner) -> Result<cyphr::Key, String> {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone())
        .map(|key| key.with_first_seen(T))
        .map_err(|e| e.to_string())
}

/// One commit by `by` of `typ` over `target`, applied to `p`, as its wire
/// bundle (SPEC 4.6.2).
async fn commit(
    p: &mut Principal,
    by: &PoolSigner,
    typ: &str,
    target: &PoolSigner,
    introduces: bool,
) -> Result<WireBundle, String> {
    let pay = serde_json::to_vec(&json!({
        "alg": by.alg, "id": target.tmb.to_b64(), "now": T,
        "tmb": by.tmb.to_b64(), "typ": typ,
    }))
    .map_err(|e| e.to_string())?;
    let (sig, cad) = coz::sign_json(&pay, &by.alg, &by.prv, &by.pubb).ok_or("sign failed")?;
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).ok_or("czd failed")?;
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(
            &pay,
            &sig,
            czd,
            introduces.then(|| key_of(target)).transpose()?,
        )
        .map_err(|e| e.to_string())?;
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&by.alg, &by.prv, &by.pubb, &by.tmb),
            T,
            "cyphr.me",
        )
        .await
        .map_err(|e| e.to_string())?;
    let last = p.commits().last().ok_or("no commit")?;
    WireBundle::of_commit(last).map_err(|e| e.to_string())
}

fn signed_part(blob: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(blob).map_err(|e| e.to_string())?;
    Ok(json!([v["pay"], v["sig"]]))
}

/// Push the fixture chain and then the replay to a fresh peer, and report
/// what the peer answered. `Err` means the observation could not be made.
pub async fn replay_on_fresh_peer(
    bins: &Bins,
    http: &reqwest::Client,
) -> Result<ReplayAnswer, String> {
    let (golden, key_a) = (pool_key(GOLDEN)?, pool_key(KEY_A)?);
    let id = golden.tmb.to_b64();

    let mut p = Principal::implicit(key_of(&golden)?)
        .await
        .map_err(|e| e.to_string())?;
    // Every chain begins with its genesis commit (SPEC 5.1).
    p.commit_genesis(
        &SoftwareSigner::new(&golden.alg, &golden.prv, &golden.pubb, &golden.tmb),
        &[],
        T,
        "cyphr.me",
    )
    .await
    .map_err(|e| e.to_string())?;
    let genesis = WireBundle::of_commit(p.commits().last().ok_or("no genesis commit")?)
        .map_err(|e| e.to_string())?;
    let c0 = commit(&mut p, &golden, "cyphr.me/cyphr/key/create", &key_a, true).await?;
    let c1 = commit(&mut p, &golden, "cyphr.me/cyphr/key/delete", &key_a, false).await?;
    let replay_blobs: Vec<Vec<u8>> = REPLAY_BLOBS
        .iter()
        .map(|b| Base64UrlUnpadded::decode_vec(b).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let c0_d = c0
        .txs
        .first()
        .and_then(|tx| tx.first())
        .ok_or("commit 0 has no coz")?;
    if signed_part(&replay_blobs[0])? != signed_part(c0_d)? {
        return Err("the recorded replay no longer re-includes commit 0's coz".into());
    }

    // A throwaway peer, so the probe leaves no principal on a scenario's.
    let peer = Peer::start(
        bins,
        "idempotency-probe",
        http,
        Role::Attestor,
        Limits::default(),
        None,
    )
    .await
    .map_err(|e| e.to_string())?;
    // The replay re-includes D as its own transaction, before the
    // recorded commit/create, with the key D names (commit 0's).
    let replay = WireBundle {
        txs: replay_blobs.into_iter().map(|b| vec![b]).collect(),
        keys: c0.keys.clone(),
        ..WireBundle::default()
    };
    let push = |bundle: &WireBundle| {
        let mut body = serde_json::to_value(bundle).unwrap_or_default();
        body["principal_id"] = id.as_str().into();
        http.post(format!("http://{}/push", peer.addr()))
            .json(&body)
            .send()
    };
    let count = || async {
        let r = http
            .get(format!("http://{}/tip", peer.addr()))
            .query(&[("pr", id.as_str())])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let v: Value = r.json().await.map_err(|e| e.to_string())?;
        v["payload"]["commit_count"]
            .as_u64()
            .ok_or_else(|| format!("no commit_count in {v}"))
    };
    for (what, blobs) in [
        ("the genesis", &genesis),
        ("commit 0", &c0),
        ("commit 1", &c1),
    ] {
        let r = push(blobs).await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            let status = r.status();
            return Err(format!(
                "{what} was refused ({status}): {}",
                r.text().await.unwrap_or_default()
            ));
        }
    }
    let count_before = count().await?;
    let r = push(&replay).await.map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    let error = body["payload"]["error"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let count_after = count().await?;
    peer.stop().await.map_err(|e| e.to_string())?;
    Ok(ReplayAnswer {
        status,
        error,
        count_before,
        count_after,
    })
}
