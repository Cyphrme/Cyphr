package storage

import "github.com/cyphrme/cyphrpass/cyphrpass"

// ExportEntries exports all entries from a Principal for storage.
//
// Returns a slice of Entry that can be persisted to any Store.
// The order is: transactions first (in apply order), then actions.
//
// Each entry contains the original raw JSON bytes from verification,
// ensuring bit-perfect round-trip fidelity for czd computation.
//
// For implicit genesis principals (Level 1, no transactions), this
// returns only actions (if any). The genesis key is not exported as
// an entry since implicit genesis has no transaction.
//
// # Example
//
//	entries := ExportEntries(principal)
//	for _, entry := range entries {
//	    store.AppendEntry(principal.PG(), entry)
//	}
func ExportEntries(principal *cyphrpass.Principal) []*Entry {
	var entries []*Entry

	// Export transactions in applied order
	for _, tx := range principal.Transactions() {
		if tx.Raw() == nil {
			// Skip transactions without raw bytes (shouldn't happen in normal flow)
			continue
		}

		entry := &Entry{
			raw: tx.Raw(),
			Now: tx.Now,
		}
		entries = append(entries, entry)
	}

	// Export actions in recorded order
	for _, action := range principal.Actions() {
		if action.Raw() == nil {
			// Skip actions without raw bytes (shouldn't happen in normal flow)
			continue
		}

		entry := &Entry{
			raw: action.Raw(),
			Now: action.Now,
		}
		entries = append(entries, entry)
	}

	return entries
}

// PersistEntries exports entries and persists them to storage.
//
// This is a convenience function that combines ExportEntries and storage.
// Returns the number of entries persisted.
func PersistEntries(store Store, principal *cyphrpass.Principal) (int, error) {
	entries := ExportEntries(principal)
	for _, entry := range entries {
		if err := store.AppendEntry(principal.PG(), entry); err != nil {
			return 0, err
		}
	}
	return len(entries), nil
}
