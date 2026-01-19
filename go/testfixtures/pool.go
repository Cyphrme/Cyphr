package testfixtures

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/cyphrme/coz"
)

// Pool contains named keys for test fixtures.
//
// The pool is loaded from tests/keys/pool.toml and provides all cryptographic
// material used in golden and intent files.
type Pool struct {
	Meta PoolMeta `toml:"pool"`

	// index for O(1) name lookup
	keyIndex map[string]*PoolKey
}

// PoolMeta contains pool metadata and keys.
type PoolMeta struct {
	Version string    `toml:"version"`
	Keys    []PoolKey `toml:"key"`
}

// PoolKey is a key in the pool.
type PoolKey struct {
	// Name is the unique identifier for this key.
	Name string `toml:"name"`
	// Alg is the algorithm (ES256, ES384, Ed25519).
	Alg string `toml:"alg"`
	// Pub is the public key (base64url).
	Pub string `toml:"pub"`
	// Prv is the private key (base64url, optional for public-only keys).
	Prv string `toml:"prv,omitempty"`
	// Tag is a human-readable description.
	Tag string `toml:"tag,omitempty"`
}

// LoadPool loads a key pool from a TOML file.
func LoadPool(path string) (*Pool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pool file: %w", err)
	}

	var pool Pool
	if err := toml.Unmarshal(data, &pool); err != nil {
		return nil, fmt.Errorf("failed to parse pool TOML: %w", err)
	}

	// Build index
	pool.keyIndex = make(map[string]*PoolKey, len(pool.Meta.Keys))
	for i := range pool.Meta.Keys {
		key := &pool.Meta.Keys[i]
		pool.keyIndex[key.Name] = key
	}

	return &pool, nil
}

// Get returns a key by name, or nil if not found.
func (p *Pool) Get(name string) *PoolKey {
	return p.keyIndex[name]
}

// Keys returns all keys in the pool.
func (p *Pool) Keys() []PoolKey {
	return p.Meta.Keys
}

// ToCozKey converts a PoolKey to a coz.Key with computed thumbprint.
//
// This is used when creating Principals from genesis keys.
func (k *PoolKey) ToCozKey() (*coz.Key, error) {
	pub, err := coz.Decode(k.Pub)
	if err != nil {
		return nil, fmt.Errorf("invalid pub base64: %w", err)
	}

	// Create key with Alg and Pub for thumbprint computation
	key := &coz.Key{
		Alg: coz.SEAlg(k.Alg),
		Pub: pub,
	}

	// Compute thumbprint (populates key.Tmb)
	if err := key.Thumbprint(); err != nil {
		return nil, fmt.Errorf("failed to compute tmb: %w", err)
	}

	return key, nil
}

// HasPrivateKey returns true if this key has private key material.
func (k *PoolKey) HasPrivateKey() bool {
	return k.Prv != ""
}
