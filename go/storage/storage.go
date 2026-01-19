// Package storage provides a backend-agnostic storage API for Cyphrpass.
//
// This package follows the "Dumb Storage, Smart Principal" design principle:
// storage stores and retrieves bytes, while all semantic operations (verification,
// state computation, key validity) belong in the cyphrpass.Principal type.
//
// # Core Types
//
//   - Entry: Raw JSON bytes preserving bit-perfect fidelity
//   - Store: Backend-agnostic interface for append-only storage
//   - Genesis: Enum representing implicit vs explicit genesis
//
// # Export/Import
//
// ExportEntries extracts entries from a Principal for storage.
// LoadPrincipal replays entries to reconstruct a Principal with full verification.
//
// # Backend Implementations
//
// This package defines the interface; implementations are in subpackages:
//
//   - storage/file: File-based JSONL storage for development/testing
//   - (future) storage/sqlite: SQLite-based storage
//   - (future) storage/postgres: PostgreSQL-based storage
//
// # Reference
//
// See docs/storage_api_design.md for the full design specification.
package storage
