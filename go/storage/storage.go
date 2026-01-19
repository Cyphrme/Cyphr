// Package storage provides storage backends for the Cyphrpass identity protocol.
//
// This package implements the storage layer for persisting Cyphrpass principals,
// transactions, and actions. The core types are:
//
//   - [Entry]: A stored entry preserving bit-perfect JSON bytes
//   - [Genesis]: Genesis type for principal creation (implicit or explicit)
//
// # Import/Export
//
// The primary functions are:
//
//   - [ExportEntries]: Export transactions and actions from a Principal
//   - [LoadPrincipal]: Reconstruct a Principal by replaying entries from genesis
//
// # Bit-Perfect Preservation
//
// Entries preserve the exact JSON bytes as received. This is critical for
// correct [coz.Czd] computation, which hashes the exact bytes of the `pay` field.
package storage
