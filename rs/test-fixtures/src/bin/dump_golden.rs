use std::fs;
use test_fixtures::{Intent, Pool, generate};

fn main() {
    let pool_str = fs::read_to_string("../tests/keys/pool.toml").unwrap();
    let pool: Pool = toml::from_str(&pool_str).unwrap();
    let intent_str = fs::read_to_string("../tests/e2e/edge_cases.toml").unwrap();
    let intent: Intent = toml::from_str(&intent_str).unwrap();
    let goldens = generate(&intent, &pool).unwrap();
    for g in goldens {
        if g.name == "action_after_key_add" {
            let s = serde_json::to_string_pretty(&g).unwrap();
            println!("{}", s);
        }
    }
}
