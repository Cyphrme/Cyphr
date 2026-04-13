// Package cyphr implements the Cyphr self-sovereign identity protocol.
//
// Cyphr enables password-free authentication via public key cryptography,
// multi-device key management, and Authenticated Atomic Actions (AAA).
//
// Built on [Coz] cryptographic JSON messaging.
//
// # Feature Levels
//
// Cyphr defines progressive feature levels:
//   - Level 1: Single static key
//   - Level 2: Key replacement
//   - Level 3: Multi-key management
//   - Level 4: Arbitrary data (Authenticated Atomic Actions)
//
// # Core Types
//
//   - [Principal]: Self-sovereign identity with permanent root (PR) and evolving state (PS)
//   - [Key]: Cryptographic key with lifecycle tracking
//   - [ParsedCoz]: Auth mutations (key/add, key/delete, key/replace, key/revoke)
//   - [Action]: Level 4 signed user actions
//
// # State Types
//
// State is computed as Merkle digests per SPEC §7:
//   - [PrincipalGenesis] (PG): Permanent identifier, set at genesis
//   - [PrincipalRoot] (PR): Current observable state root
//   - [AuthRoot] (AR): Authentication state from keyset
//   - [StateRoot] (SR): Context-binding root: MR(AR, DR?, embedding?)
//   - [KeyRoot] (KR): Digest of active key thumbprints
//   - [CommitRoot] (CR): Identity of a commit (Merkle root of coz czds)
//   - [DataRoot] (DR): Digest of action czds (Level 4)
//
// # Genesis
//
// Create a principal using one of:
//   - [Implicit]: Single-key genesis (Level 1/2)
//   - [Explicit]: Multi-key genesis (Level 3+)
//
// # Example
//
//	key, _ := coz.NewKey(coz.ES256)
//	principal, _ := cyphr.Implicit(key)
//	fmt.Println(principal.PG())  // Permanent identifier
//
// [Coz]: https://github.com/Cyphrme/Coz
package cyphr

// Authority is the Cyphr typ authority prefix.
const Authority = "cyphr.me"

// Version is the protocol version implemented by this package.
const Version = "0.0.1"
