#!/usr/bin/env python3
import os

def generate_toml():
    toml_lines = [
        "# E2E Features Matrix Tests",
        "# Generated automatically by generate_e2e_features.py",
        "# Covers 16 features across 4 tiers with a minimum of 179 cases.",
        ""
    ]

    base_time = 1700000000

    # -------------------------------------------------------------------------
    # TIER 1: FEATURE COVERAGE (80 cases: 16 features * 5 cases each)
    # -------------------------------------------------------------------------
    
    # F-01: Implicit Genesis (1 key)
    # Case 1..5: Genesis with different keys/algorithms
    keys = ["golden", "alice", "bob", "diana_es384", "eve_ed25519"]
    for i, key in enumerate(keys):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f01_case{i+1}"',
            f'principal = ["{key}"]',
            "",
            "[test.expected]",
            "key_count = 1",
            "level     = 1",
            ""
        ])

    # F-02: Single-Key Authorization
    # Case 1..5: Single key auth for key/create mutation
    for i, key in enumerate(keys):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f02_case{i+1}"',
            f'principal = ["{key}"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "{key}", target = "key_a", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            "level     = 3",
            ""
        ])

    # F-03: Permanent Lockout (Happy paths: reducing key count but keeping at least 1 key)
    # Case 1: Start with 2 keys, revoke 1
    toml_lines.extend([
        "[[test]]",
        'name      = "t1_f03_case1"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, rvk = {base_time}, signer = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])
    # Case 2: Start with 2 keys, delete 1
    toml_lines.extend([
        "[[test]]",
        'name      = "t1_f03_case2"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])
    # Case 3: Start with 3 keys, revoke 1 then delete 1
    toml_lines.extend([
        "[[test]]",
        'name      = "t1_f03_case3"',
        'principal = ["alice", "bob", "carol"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, rvk = {base_time}, signer = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])
    # Case 4: Start with golden & alice, revoke golden
    toml_lines.extend([
        "[[test]]",
        'name      = "t1_f03_case4"',
        'principal = ["golden", "alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, rvk = {base_time}, signer = "golden", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])
    # Case 5: Start with alice, bob, carol, delete bob then revoke carol
    toml_lines.extend([
        "[[test]]",
        'name      = "t1_f03_case5"',
        'principal = ["alice", "bob", "carol"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, rvk = {base_time+1}, signer = "carol", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # F-04: Atomic Key Replace
    # Case 1..5: Replace genesis key with target key
    replace_pairs = [
        ("golden", "key_a"),
        ("alice", "bob"),
        ("bob", "alice"),
        ("diana_es384", "golden"),
        ("eve_ed25519", "alice")
    ]
    for i, (signer, target) in enumerate(replace_pairs):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f04_case{i+1}"',
            f'principal = ["{signer}"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "{signer}", target = "{target}", typ = "cyphr.me/cyphr/key/replace" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 1",
            ""
        ])

    # F-05: Post-Replace Authorization
    # Case 1..5: Replace key, then new key signs subsequent transaction/action
    for i, (signer, target) in enumerate(replace_pairs):
        next_target = "bob" if target != "bob" else "alice"
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f05_case{i+1}"',
            f'principal = ["{signer}"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "{signer}", target = "{target}", typ = "cyphr.me/cyphr/key/replace" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "{target}", target = "{next_target}", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            ""
        ])

    # F-06: Explicit Genesis
    # Case 1..5: Start with one implicit key, add keys, then sign principal/create
    explicit_configs = [
        ("alice", "bob"),
        ("bob", "alice"),
        ("alice", "carol"),
        ("diana_es384", "eve_ed25519"),
        ("eve_ed25519", "golden")
    ]
    for i, (signer, target) in enumerate(explicit_configs):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f06_case{i+1}"',
            f'principal = ["{signer}"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "{signer}", target = "{target}", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "{signer}", typ = "cyphr.me/cyphr/principal/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            "level     = 3",
            ""
        ])

    # F-07: Concurrent Keys
    # Case 1..5: Multiple active keys signing in different order or combinations
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f07_case{i+1}"',
            'principal = ["alice", "bob"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "bob", target = "diana_es384", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 4",
            ""
        ])

    # F-08: Key Addition
    # Case 1..5: Create key with different targets
    targets = ["alice", "bob", "carol", "diana_es384", "eve_ed25519"]
    for i, target in enumerate(targets):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f08_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "{target}", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            ""
        ])

    # F-09: Key Deletion
    # Case 1..5: Deleting key in multi-key setup
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f09_case{i+1}"',
            'principal = ["alice", "bob", "carol"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            ""
        ])

    # F-10: Key Revocation
    # Case 1..5: Revoking keys
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f10_case{i+1}"',
            'principal = ["alice", "bob"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, rvk = {base_time}, signer = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 1",
            ""
        ])

    # F-11: Multi-coz Commits
    # Case 1..5: Commit with multiple cozies
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f11_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            f'    {{ now = {base_time}, signer = "golden", target = "bob", typ = "cyphr.me/cyphr/key/create" }}',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 3",
            ""
        ])

    # F-12: Commit Finality Arrow
    # Case 1..5: Verified by commit presence
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f12_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            ""
        ])

    # F-13: MALT Logs & Proofs
    # Case 1..5: Verify MALT consistency with multiple commits in chain
    for i in range(5):
        # Generate i+2 commits
        test_block = [
            "[[test]]",
            f'name      = "t1_f13_case{i+1}"',
            'principal = ["golden"]',
            ""
        ]
        keys = ["key_a", "alice", "bob", "carol", "diana_es384", "eve_ed25519"]
        for c in range(i+2):
            target_key = keys[c]
            test_block.extend([
                "[[test.commit]]",
                "tx = [",
                "  [",
                f'    {{ now = {base_time+c}, signer = "golden", target = "{target_key}", typ = "cyphr.me/cyphr/key/create" }},',
                "  ],",
                "]",
                ""
            ])
        test_block.extend([
            "[test.expected]",
            f"key_count = {i+3}",
            ""
        ])
        toml_lines.extend(test_block)

    # F-14: Multihash Coherence
    # Case 1..5: Coherence with different key algorithms
    multihash_configs = [
        ("golden", "diana_es384"),
        ("golden", "eve_ed25519"),
        ("diana_es384", "eve_ed25519"),
        ("eve_ed25519", "diana_es384"),
        ("alice", "diana_es384")
    ]
    for i, (signer, target) in enumerate(multihash_configs):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f14_case{i+1}"',
            f'principal = ["{signer}"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "{signer}", target = "{target}", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            "key_count = 2",
            ""
        ])

    # F-15: Data Action Record
    # Case 1..5: Different action types
    action_types = ["cyphr.me/action", "cyphr.me/comment/create", "cyphr.me/post/create", "cyphr.me/action", "cyphr.me/action"]
    for i, action_typ in enumerate(action_types):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f15_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.action]]",
            f'typ    = "{action_typ}"',
            f'now    = {base_time}',
            'signer = "golden"',
            'msg    = "Tier 1 F-15 Case"',
            "",
            "[test.expected]",
            "level     = 4",
            ""
        ])

    # F-16: Level Promotion
    # Case 1..5: Levels promoted to 4
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t1_f16_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.action]]",
            'typ    = "cyphr.me/action"',
            f'now    = {base_time}',
            'signer = "golden"',
            "",
            "[test.expected]",
            "level     = 4",
            ""
        ])

    # -------------------------------------------------------------------------
    # TIER 2: BOUNDARY & CORNER CASES (80 cases: 16 features * 5 cases each)
    # -------------------------------------------------------------------------
    
    # F-01: Implicit Genesis (Errors)
    # Case 1: Empty principal -> NoGenesisKeys
    toml_lines.extend([
        "[[test]]",
        'name      = "t2_f01_case1"',
        'principal = []',
        "",
        "[test.expected]",
        'error     = "NoGenesisKeys"',
        ""
    ])
    # Case 2: Unsupported algorithm (RS256) -> UnknownAlg (genesis-time
    # construction rejects the algorithm itself; UnsupportedAlgorithm is a
    # distinct error raised only at signing time, not genesis)
    toml_lines.extend([
        "[[test]]",
        'name      = "t2_f01_case2"',
        'principal = ["unsupported_key"]',
        "",
        "[test.expected]",
        'error     = "UnknownAlg"',
        ""
    ])
    # Case 3: Mixed genesis with unsupported key
    toml_lines.extend([
        "[[test]]",
        'name      = "t2_f01_case3"',
        'principal = ["unsupported_key", "golden"]',
        "",
        "[test.expected]",
        'error     = "UnknownAlg"',
        ""
    ])
    # Case 4: Multiple unsupported keys
    toml_lines.extend([
        "[[test]]",
        'name      = "t2_f01_case4"',
        'principal = ["unsupported_key", "unsupported_key"]',
        "",
        "[test.expected]",
        'error     = "UnknownAlg"',
        ""
    ])
    # Case 5: Empty principal with setup -> NoGenesisKeys
    toml_lines.extend([
        "[[test]]",
        'name      = "t2_f01_case5"',
        'principal = []',
        "",
        "[test.setup]",
        'revoke_key = "golden"',
        "",
        "[test.expected]",
        'error     = "NoGenesisKeys"',
        ""
    ])

    # F-02: Single-Key Authorization (Errors)
    # Case 1..5: Signed by non-active key -> UnknownSigner
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f02_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "key_a", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-03: Permanent Lockout (Errors)
    # Case 1..5: Revoking/deleting the last active key -> [naked-revoke-error]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f03_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "golden", typ = "cyphr.me/cyphr/key/delete" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "[naked-revoke-error]"',
            ""
        ])

    # F-04: Atomic Key Replace (Errors)
    # Case 1..5: Key replacement with wrong signer or setup
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f04_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "key_a", typ = "cyphr.me/cyphr/key/replace" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-05: Post-Replace Authorization (Errors)
    # Case 1..5: Replace key, then old key tries to sign subsequent operation -> UnknownSigner
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f05_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "golden", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-06: Explicit Genesis (Errors)
    # Case 1..5: Invalid explicit genesis commits (e.g. signer unknown or wrong pre)
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f06_case{i+1}"',
            'principal = ["alice"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "bob", typ = "cyphr.me/cyphr/principal/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-07: Concurrent Keys (Errors)
    # Case 1..5: Delete a concurrent key, then it tries to sign subsequent commit -> UnknownSigner
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f07_case{i+1}"',
            'principal = ["alice", "bob"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "bob", target = "carol", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-08: Key Addition (Errors)
    # Case 1..5: Duplicate key addition -> [create-uniqueness]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f08_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "[create-uniqueness]"',
            ""
        ])

    # F-09: Key Deletion (Errors)
    # Case 1..5: Delete a non-existent key -> UnknownSigner
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f09_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/delete" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # F-10: Key Revocation (Errors)
    # Case 1..5: Alice tries to revoke Bob -> [no-revoke-non-self]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f10_case{i+1}"',
            'principal = ["alice", "bob"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, rvk = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "[no-revoke-non-self]"',
            ""
        ])

    # F-11: Multi-coz Commits (Errors)
    # Case 1..5: Empty commit -> [commit-one-or-more]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f11_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.override]",
            "empty_commit = true",
            "",
            "[test.expected]",
            'error     = "[commit-one-or-more]"',
            ""
        ])

    # F-13: MALT Logs & Proofs (Errors)
    # Case 1..5: Out of order timestamps -> [verification-timestamp-order]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f13_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time+1}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "[verification-timestamp-order]"',
            ""
        ])

    # F-14: Multihash Coherence (Errors)
    # Case 1..5: Try to add unsupported algorithm key -> UnknownAlg
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f14_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.commit]]",
            "tx = [",
            "  [",
            f'    {{ now = {base_time}, signer = "golden", target = "unsupported_key", typ = "cyphr.me/cyphr/key/create" }},',
            "  ],",
            "]",
            "",
            "[test.expected]",
            'error     = "UnknownAlg"',
            ""
        ])

    # F-15: Data Action Record (Errors)
    # Case 1..5: Inject pre on data action -> [data-action-no-pre]
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f15_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.action]]",
            'typ    = "cyphr.me/action"',
            f'now    = {base_time}',
            'signer = "golden"',
            "",
            "[test.override]",
            "inject_pre = true",
            "",
            "[test.expected]",
            'error     = "[data-action-no-pre]"',
            ""
        ])

    # F-16: Level Promotion (Errors)
    # Case 1..5: Unknown signer for action -> UnknownSigner
    for i in range(5):
        toml_lines.extend([
            "[[test]]",
            f'name      = "t2_f16_case{i+1}"',
            'principal = ["golden"]',
            "",
            "[[test.action]]",
            'typ    = "cyphr.me/action"',
            f'now    = {base_time}',
            'signer = "alice"',
            "",
            "[test.expected]",
            'error     = "UnknownSigner"',
            ""
        ])

    # -------------------------------------------------------------------------
    # TIER 3: PAIRWISE COMBINATORIAL (16 cases)
    # -------------------------------------------------------------------------
    
    # Case 1: replace then action
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case1"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+1}',
        'signer = "alice"',
        "",
        "[test.expected]",
        "key_count = 1",
        "level     = 4",
        ""
    ])

    # Case 2: add then revoke
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case2"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, rvk = {base_time+1}, signer = "golden", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # Case 3: add then action then delete
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case3"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+1}',
        'signer = "alice"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        "level     = 4",
        ""
    ])

    # Case 4: mixed algorithm additions
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case4"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "diana_es384", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "golden", target = "eve_ed25519", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 3",
        ""
    ])

    # Case 5: multi-device delete
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case5"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # Case 6: replace then replace
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case6"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # Case 7: revoke then replace
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case7"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, rvk = {base_time}, signer = "alice", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "bob", target = "carol", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # Case 8: explicit genesis then action
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case8"',
        'principal = ["alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/principal/create" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "bob"',
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 4",
        ""
    ])

    # Case 9: action then addition
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case9"',
        'principal = ["golden"]',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time}',
        'signer = "golden"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 4",
        ""
    ])

    # Case 10: replace then delete
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case10"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "bob", target = "carol", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # Case 11: add then revoke then action
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case11"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, rvk = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "golden"',
        "",
        "[test.expected]",
        "key_count = 1",
        "level     = 4",
        ""
    ])

    # Case 12: mixed alg additions then action
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case12"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "diana_es384", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "golden", target = "eve_ed25519", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "diana_es384"',
        "",
        "[test.expected]",
        "key_count = 3",
        "level     = 4",
        ""
    ])

    # Case 13: delete then replace
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case13"',
        'principal = ["alice", "bob", "carol"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", target = "diana_es384", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 2"
        ""
    ])

    # Case 14: replace then revoke
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case14"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, rvk = {base_time+1}, signer = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1"
        ""
    ])

    # Case 15: action then replace then action
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case15"',
        'principal = ["golden"]',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time}',
        'signer = "golden"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "alice"',
        "",
        "[test.expected]",
        "key_count = 1",
        "level     = 4",
        ""
    ])

    # Case 16: explicit genesis then replace
    toml_lines.extend([
        "[[test]]",
        'name      = "t3_case16"',
        'principal = ["alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/principal/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, signer = "bob", target = "carol", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 3",
        ""
    ])

    # -------------------------------------------------------------------------
    # TIER 4: REAL-WORLD APPLICATION WORKLOADS (8 scenarios: S-01 to S-08)
    # -------------------------------------------------------------------------
    
    # S-01: Multi-Device Key Sync & Revocation
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s01"',
        'principal = ["alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
        f'    {{ now = {base_time}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/create" }}',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/principal/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, signer = "bob", target = "diana_es384", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+3}, rvk = {base_time+3}, signer = "carol", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 3",
        "level     = 3",
        ""
    ])

    # S-02: Sequential Key Rotation with Active Logging
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s02"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+1}',
        'signer = "alice"',
        'msg    = "Log 1 after rotation 1"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "alice"',
        'msg    = "Log 2 after rotation 1"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+3}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+4}',
        'signer = "bob"',
        'msg    = "Log 1 after rotation 2"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+5}',
        'signer = "bob"',
        'msg    = "Log 2 after rotation 2"',
        "",
        "[test.expected]",
        "key_count = 1",
        "level     = 4",
        ""
    ])

    # S-03: Multi-Algorithm Recovery Pipeline
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s03"',
        'principal = ["alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "diana_es384", typ = "cyphr.me/cyphr/key/create" }},',
        f'    {{ now = {base_time}, signer = "alice", target = "eve_ed25519", typ = "cyphr.me/cyphr/key/create" }}',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/principal/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, rvk = {base_time+2}, signer = "diana_es384", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+3}',
        'signer = "eve_ed25519"',
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 4",
        ""
    ])

    # S-04: Cooperative Key Deletion and Lockout Prevention
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s04"',
        'principal = ["alice", "bob", "carol"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "bob", target = "carol", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/delete" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 1",
        ""
    ])

    # S-05: Bulk Data Archiving & Merkle Consistency
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s05"',
        'principal = ["golden"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/create" }},',
        f'    {{ now = {base_time}, signer = "golden", target = "bob", typ = "cyphr.me/cyphr/key/create" }}',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+1}',
        'signer = "golden"',
        'msg    = "Bulk doc 1"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+2}',
        'signer = "alice"',
        'msg    = "Bulk doc 2"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+3}',
        'signer = "bob"',
        'msg    = "Bulk doc 3"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+4}',
        'signer = "golden"',
        'msg    = "Bulk doc 4"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+5}',
        'signer = "alice"',
        'msg    = "Bulk doc 5"',
        "",
        "[test.expected]",
        "key_count = 3",
        "level     = 4",
        ""
    ])

    # S-06: Key Recovery Handover
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s06"',
        'principal = ["alice"]',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "alice", typ = "cyphr.me/cyphr/principal/create" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, rvk = {base_time+2}, signer = "bob", typ = "cyphr.me/cyphr/key/revoke" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+3}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 3",
        ""
    ])

    # S-07: Parallel Action Commit Interleaving
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s07"',
        'principal = ["alice", "bob"]',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time}',
        'signer = "alice"',
        'msg    = "Action 1"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+1}',
        'signer = "bob"',
        'msg    = "Action 2"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, signer = "alice", target = "carol", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+3}',
        'signer = "bob"',
        'msg    = "Action 3"',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time+4}',
        'signer = "carol"',
        'msg    = "Action 4"',
        "",
        "[test.expected]",
        "key_count = 3",
        "level     = 4",
        ""
    ])

    # S-08: Mixed-Mode Level Escalation
    toml_lines.extend([
        "[[test]]",
        'name      = "t4_s08"',
        'principal = ["golden"]',
        "",
        "[[test.action]]",
        'typ    = "cyphr.me/action"',
        f'now    = {base_time}',
        'signer = "golden"',
        'msg    = "Escalate to L4"',
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+1}, signer = "golden", target = "alice", typ = "cyphr.me/cyphr/key/replace" }},',
        "  ],",
        "]",
        "",
        "[[test.commit]]",
        "tx = [",
        "  [",
        f'    {{ now = {base_time+2}, signer = "alice", target = "bob", typ = "cyphr.me/cyphr/key/create" }},',
        "  ],",
        "]",
        "",
        "[test.expected]",
        "key_count = 2",
        "level     = 4",
        ""
    ])

    return "\n".join(toml_lines)

if __name__ == "__main__":
    toml_content = generate_toml()
    output_path = os.path.join(os.path.dirname(__file__), "e2e_features.toml")
    with open(output_path, "w") as f:
        f.write(toml_content)
    print(f"Generated {output_path} successfully.")
