package storage

// Genesis represents how a principal was created.
type Genesis interface {
	isGenesis()
}

// ImplicitGenesis creates a principal from a single key (Level 1/2).
type ImplicitGenesis struct {
	// Key is the genesis key material.
	Alg string
	Pub []byte
	Tmb []byte
}

func (ImplicitGenesis) isGenesis() {}

// ExplicitGenesis creates a principal from multiple keys (Level 3+).
type ExplicitGenesis struct {
	// Keys are the genesis key materials.
	Keys []GenesisKey
}

func (ExplicitGenesis) isGenesis() {}

// GenesisKey is key material for explicit genesis.
type GenesisKey struct {
	Alg string
	Pub []byte
	Tmb []byte
}

// TODO: Implement LoadPrincipal once cyphrpass package is importable.
//
// LoadPrincipal loads a principal by replaying entries from genesis.
//
// This performs full verification of the entire transaction history.
