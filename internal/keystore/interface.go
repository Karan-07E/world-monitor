// Package keystore defines the HSM abstraction interface and implementations.
package keystore

import "context"

// KeyStore defines the interface for cryptographic key management.
// This abstraction allows swapping between SoftHSM2, PKCS#11 hardware HSMs,
// and in-memory implementations.
type KeyStore interface {
	// GenerateMLKEMKeyPair generates an ML-KEM-768 key pair and stores it.
	// Returns the key ID for later retrieval.
	GenerateMLKEMKeyPair(ctx context.Context, keyID string) error

	// GenerateMLDSAKeyPair generates an ML-DSA-65 key pair and stores it.
	// Returns the key ID for later retrieval.
	GenerateMLDSAKeyPair(ctx context.Context, keyID string) error

	// GetMLKEMPublicKey retrieves the ML-KEM-768 public key by key ID.
	GetMLKEMPublicKey(ctx context.Context, keyID string) ([]byte, error)

	// GetMLDSAPublicKey retrieves the ML-DSA-65 public key by key ID.
	GetMLDSAPublicKey(ctx context.Context, keyID string) ([]byte, error)

	// DecapsulateMLKEM performs ML-KEM-768 decapsulation using the stored private key.
	// The private key never leaves the HSM boundary.
	DecapsulateMLKEM(ctx context.Context, keyID string, ciphertext []byte) (sharedSecret []byte, err error)

	// SignMLDSA signs a message using the stored ML-DSA-65 private key.
	// The private key never leaves the HSM boundary.
	SignMLDSA(ctx context.Context, keyID string, message []byte) (signature []byte, err error)

	// VerifyMLDSA verifies an ML-DSA-65 signature using the stored public key.
	VerifyMLDSA(ctx context.Context, keyID string, message, signature []byte) (bool, error)

	// HasKey checks whether a key exists in the store.
	HasKey(ctx context.Context, keyID string) (bool, error)

	// ListKeys returns all key IDs in the store.
	ListKeys(ctx context.Context) ([]string, error)

	// Close releases resources held by the key store.
	Close() error
}

// KeyType represents the type of cryptographic key.
type KeyType string

const (
	KeyTypeMLKEM KeyType = "ML-KEM-768"
	KeyTypeMLDSA KeyType = "ML-DSA-65"
)

// KeyMetadata holds metadata about a stored key.
type KeyMetadata struct {
	KeyID     string  `json:"key_id"`
	KeyType   KeyType `json:"key_type"`
	Algorithm string  `json:"algorithm"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"`
}
