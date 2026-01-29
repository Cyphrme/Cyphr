//! Fixture-gen CLI for Cyphrpass test fixtures.
//!
//! Commands:
//! - `generate`: Transform intent TOML → golden JSON
//! - `pool`: Key pool management

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fixture-gen")]
#[command(about = "Generate and manage Cyphrpass test fixtures")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to key pool file
    #[arg(long, default_value = "tests/keys/pool.toml", global = true)]
    pool: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate golden JSON from intent TOML
    Generate {
        /// Intent TOML file or directory (with -r)
        input: PathBuf,
        /// Output JSON file or directory (with -r)
        output: PathBuf,
        /// Recursive mode: process all .toml files in directory
        #[arg(short, long)]
        recursive: bool,
    },
    /// Key pool management
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
}

#[derive(Subcommand)]
enum PoolCmd {
    /// Validate pool file
    Validate,
    /// List all keys
    List,
    /// Add a new key
    Add {
        /// Key name
        name: String,
        /// Algorithm (ES256, ES384, Ed25519)
        alg: String,
    },
    /// Remove a key
    Remove {
        /// Key name
        name: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            input,
            output,
            recursive,
        } => {
            // Load pool
            let pool = match test_fixtures::Pool::load(&cli.pool) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("✗ Failed to load pool '{}': {}", cli.pool.display(), e);
                    std::process::exit(1);
                },
            };

            if recursive {
                generate_recursive(&input, &output, &pool);
            } else {
                generate_single(&input, &output, &pool);
            }
        },
        Commands::Pool { cmd } => match cmd {
            PoolCmd::Validate => {
                println!("Validating pool: {:?}", cli.pool);
                match test_fixtures::Pool::load(&cli.pool) {
                    Ok(pool) => match pool.validate() {
                        Ok(()) => println!("✓ Pool is valid"),
                        Err(errors) => {
                            for e in errors {
                                eprintln!("✗ {}", e);
                            }
                            std::process::exit(1);
                        },
                    },
                    Err(e) => {
                        eprintln!("✗ Failed to load pool: {}", e);
                        std::process::exit(1);
                    },
                }
            },
            PoolCmd::List => {
                println!("Listing keys from: {:?}", cli.pool);
                match test_fixtures::Pool::load(&cli.pool) {
                    Ok(pool) => {
                        for key in &pool.pool.key {
                            println!("  {} ({})", key.name, key.alg);
                            if let Some(tag) = &key.tag {
                                println!("    tag: {}", tag);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("✗ Failed to load pool: {}", e);
                        std::process::exit(1);
                    },
                }
            },
            PoolCmd::Add { name, alg } => {
                add_key_to_pool(&cli.pool, &name, &alg);
            },
            PoolCmd::Remove { name } => {
                remove_key_from_pool(&cli.pool, &name);
            },
        },
    }
}

/// Generate from a single intent file to a single output file (array of goldens).
fn generate_single(intent_path: &Path, output_path: &PathBuf, pool: &test_fixtures::Pool) {
    let intent_data = match test_fixtures::Intent::load(intent_path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("✗ Failed to load intent '{}': {}", intent_path.display(), e);
            std::process::exit(1);
        },
    };

    let goldens = match test_fixtures::generate(&intent_data, pool) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("✗ Generation failed: {}", e);
            std::process::exit(1);
        },
    };

    let json = match serde_json::to_string_pretty(&goldens) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("✗ Failed to serialize output: {}", e);
            std::process::exit(1);
        },
    };

    // Create parent directories if needed
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "✗ Failed to create output directory '{}': {}",
                    parent.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = std::fs::write(output_path, &json) {
        eprintln!(
            "✗ Failed to write output '{}': {}",
            output_path.display(),
            e
        );
        std::process::exit(1);
    }

    println!(
        "✓ Generated {} test case(s) → {}",
        goldens.len(),
        output_path.display()
    );
}

/// Generate recursively: each .toml in input_dir produces a subdirectory
/// with per-test JSON files.
///
/// Structure: input_dir/genesis.toml (with test1, test2)
///         → output_dir/genesis/test1.json, output_dir/genesis/test2.json
fn generate_recursive(input_dir: &PathBuf, output_dir: &Path, pool: &test_fixtures::Pool) {
    if !input_dir.is_dir() {
        eprintln!(
            "✗ Input path '{}' is not a directory (use -r only with directories)",
            input_dir.display()
        );
        std::process::exit(1);
    }

    // Collect all .toml files
    let toml_files: Vec<_> = match std::fs::read_dir(input_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect(),
        Err(e) => {
            eprintln!(
                "✗ Failed to read input directory '{}': {}",
                input_dir.display(),
                e
            );
            std::process::exit(1);
        },
    };

    if toml_files.is_empty() {
        eprintln!("✗ No .toml files found in '{}'", input_dir.display());
        std::process::exit(1);
    }

    let mut total_tests = 0;
    let mut total_files = 0;

    for toml_path in &toml_files {
        let intent_data = match test_fixtures::Intent::load(toml_path) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("✗ Failed to load intent '{}': {}", toml_path.display(), e);
                std::process::exit(1);
            },
        };

        let goldens = match test_fixtures::generate(&intent_data, pool) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("✗ Generation failed for '{}': {}", toml_path.display(), e);
                std::process::exit(1);
            },
        };

        // Create subdirectory based on intent file basename
        let intent_stem = toml_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let subdir = output_dir.join(intent_stem);

        if let Err(e) = std::fs::create_dir_all(&subdir) {
            eprintln!(
                "✗ Failed to create output directory '{}': {}",
                subdir.display(),
                e
            );
            std::process::exit(1);
        }

        // Write each test as a separate JSON file
        for golden in &goldens {
            let test_file = subdir.join(format!("{}.json", golden.name));
            let json = match serde_json::to_string_pretty(&golden) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("✗ Failed to serialize '{}': {}", golden.name, e);
                    std::process::exit(1);
                },
            };

            if let Err(e) = std::fs::write(&test_file, &json) {
                eprintln!("✗ Failed to write '{}': {}", test_file.display(), e);
                std::process::exit(1);
            }

            total_tests += 1;
        }

        total_files += 1;
        println!(
            "  {} → {}/",
            toml_path.file_name().unwrap_or_default().to_string_lossy(),
            intent_stem
        );
    }

    println!(
        "✓ Generated {} test(s) from {} intent file(s) → {}",
        total_tests,
        total_files,
        output_dir.display()
    );
}

/// Add a new key to the pool file.
fn add_key_to_pool(pool_path: &Path, name: &str, alg: &str) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    // Load existing pool
    let mut pool = match test_fixtures::Pool::load(pool_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Failed to load pool '{}': {}", pool_path.display(), e);
            std::process::exit(1);
        },
    };

    // Check for duplicate name
    if pool.get(name).is_some() {
        eprintln!("✗ Key '{}' already exists in pool", name);
        std::process::exit(1);
    }

    // Generate key using Alg enum for type-safe dispatch
    let alg_enum = match coz::Alg::from_str(alg) {
        Some(a) => a,
        None => {
            eprintln!(
                "✗ Unsupported algorithm '{}'. Use: ES256, ES384, ES512, Ed25519",
                alg
            );
            std::process::exit(1);
        },
    };

    let keypair = alg_enum.generate_keypair();
    let pub_b64 = Base64UrlUnpadded::encode_string(&keypair.pub_bytes);
    let prv_b64 = Base64UrlUnpadded::encode_string(&keypair.prv_bytes);

    // Create new key entry
    let new_key = test_fixtures::PoolKey {
        name: name.to_string(),
        alg: alg.to_string(),
        pub_key: pub_b64,
        prv: Some(prv_b64),
        tag: None,
    };

    // Add to pool
    pool.pool.key.push(new_key);

    // Write back to file
    let toml_content = toml::to_string_pretty(&pool).expect("TOML serialization cannot fail");
    if let Err(e) = std::fs::write(pool_path, toml_content) {
        eprintln!("✗ Failed to write pool '{}': {}", pool_path.display(), e);
        std::process::exit(1);
    }

    println!(
        "✓ Added key '{}' ({}) to {}",
        name,
        alg,
        pool_path.display()
    );
}

/// Remove a key from the pool file.
fn remove_key_from_pool(pool_path: &Path, name: &str) {
    // Load existing pool
    let mut pool = match test_fixtures::Pool::load(pool_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Failed to load pool '{}': {}", pool_path.display(), e);
            std::process::exit(1);
        },
    };

    // Find and remove key
    let original_len = pool.pool.key.len();
    pool.pool.key.retain(|k| k.name != name);

    if pool.pool.key.len() == original_len {
        eprintln!("✗ Key '{}' not found in pool", name);
        std::process::exit(1);
    }

    // Write back to file
    let toml_content = toml::to_string_pretty(&pool).expect("TOML serialization cannot fail");
    if let Err(e) = std::fs::write(pool_path, toml_content) {
        eprintln!("✗ Failed to write pool '{}': {}", pool_path.display(), e);
        std::process::exit(1);
    }

    println!("✓ Removed key '{}' from {}", name, pool_path.display());
}
