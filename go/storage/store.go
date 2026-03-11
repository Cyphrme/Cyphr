package storage

import "github.com/cyphrme/cyphrpass/cyphrpass"

// Store defines the minimal interface for Cyphrpass storage backends.
//
// Storage is intentionally simple — Cyphrpass handles all semantic operations.
// This follows the "dumb storage, smart Principal" design principle.
//
// The interface stores raw bytes (signed Coz messages). All verification,
// state computation, and key validity checks belong in the Principal type.
type Store interface {
	// AppendEntry appends a signed entry (transaction or action) to the log.
	// The entry must be a valid signed Coz JSON message.
	AppendEntry(pr *cyphrpass.PrincipalRoot, entry *Entry) error

	// GetEntries returns all entries for a principal in storage order.
	GetEntries(pr *cyphrpass.PrincipalRoot) ([]*Entry, error)

	// GetEntriesRange returns entries with pagination/filtering.
	// Supports transaction patches for checkpoint-based sync.
	GetEntriesRange(pr *cyphrpass.PrincipalRoot, opts *QueryOpts) ([]*Entry, error)

	// Exists checks if a principal exists in storage.
	Exists(pr *cyphrpass.PrincipalRoot) (bool, error)
}

// QueryOpts provides common query parameters for filtered retrieval.
type QueryOpts struct {
	// Limit is the maximum number of entries to return. 0 means no limit.
	Limit int

	// Offset is the number of entries to skip. 0 means start from beginning.
	Offset int

	// After filters to entries with pay.now > After. 0 means no filter.
	After int64

	// Before filters to entries with pay.now < Before. 0 means no filter.
	Before int64
}
