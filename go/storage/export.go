package storage

// TODO: Implement ExportEntries once cyphrpass package is importable.
//
// ExportEntries exports all entries from a Principal for storage.
//
// Returns a slice of Entry that can be persisted to any Store.
// The order is: transactions first (in apply order), then actions.
//
// For key/add and key/replace transactions, the associated key material
// is included in the exported entry as a `key` field, matching SPEC §3.1 JSONL format.
