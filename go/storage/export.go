package storage

import "github.com/cyphrme/cyphr/cyphr"

// ExportEntries exports all entries from a Principal for storage.
//
// Returns a slice of Entry that can be persisted to any Store.
// The order is: all cozies per commit (mutations then commit transaction),
// followed by actions.
//
// Each entry contains the original raw JSON bytes from verification,
// ensuring bit-perfect round-trip fidelity for czd computation.
//
// For implicit genesis principals (Level 1, no commits), this
// returns only actions (if any). The genesis key is not exported as
// an entry since implicit genesis has no coz.
//
// # Example
//
//	entries := ExportEntries(principal)
//	for _, entry := range entries {
//	    store.AppendEntry(principal.PG(), entry)
//	}
func ExportEntries(principal *cyphr.Principal) []*Entry {
	var entries []*Entry

	// Export cozies per commit, preserving commit boundaries.
	// Each commit contains mutation cozies followed by the commit transaction
	// coz (which has the arrow field marking the commit boundary).
	for _, commit := range principal.Commits() {
		for _, cz := range commit.Cozies() {
			if cz.Raw() == nil {
				// Skip cozies without raw bytes (shouldn't happen in normal flow)
				continue
			}

			entry := &Entry{
				raw: cz.Raw(),
				Now: cz.Now,
			}
			entries = append(entries, entry)
		}
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
func PersistEntries(store Store, principal *cyphr.Principal) (int, error) {
	entries := ExportEntries(principal)
	for _, entry := range entries {
		if err := store.AppendEntry(principal.PG(), entry); err != nil {
			return 0, err
		}
	}
	return len(entries), nil
}
