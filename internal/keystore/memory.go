// Package keystore provides a memory-based KeyStore implementation.
package keystore

import (
	"context"
	"fmt"
	"sync"

	"github.com/cryptoattr/secure-doc-dist/internal/crypto/mlkem"
	"github.com/cryptoattr/secure-doc-dist/internal/crypto/mldsa"
)

// storedKey holds the serialized key material for a single key.
type storedKey struct {
	keyType    KeyType
	publicKey  []byte
	privateKey []byte
}

// MemoryKeyStore implements KeyStore with in-memory storage.
// Suitable for testing and demo environments.
// WARNING: Keys are lost when the process exits.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*storedKey
}

// NewMemoryKeyStore creates a new in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]*storedKey),
	}
}

func (m *MemoryKeyStore) GenerateMLKEMKeyPair(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[keyID]; exists {
		return fmt.Errorf("key already exists: %s", keyID)
	}

	kp, err := mlkem.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generating ML-KEM keypair: %w", err)
	}

	pubBytes, err := mlkem.MarshalPublicKey(kp.PublicKey)
	if err != nil {
		return err
	}
	privBytes, err := mlkem.MarshalPrivateKey(kp.PrivateKey)
	if err != nil {
		return err
	}

	m.keys[keyID] = &storedKey{
		keyType:    KeyTypeMLKEM,
		publicKey:  pubBytes,
		privateKey: privBytes,
	}
	return nil
}

func (m *MemoryKeyStore) GenerateMLDSAKeyPair(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[keyID]; exists {
		return fmt.Errorf("key already exists: %s", keyID)
	}

	kp, err := mldsa.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generating ML-DSA keypair: %w", err)
	}

	pubBytes, err := mldsa.MarshalPublicKey(kp.PublicKey)
	if err != nil {
		return err
	}
	privBytes, err := mldsa.MarshalPrivateKey(kp.PrivateKey)
	if err != nil {
		return err
	}

	m.keys[keyID] = &storedKey{
		keyType:    KeyTypeMLDSA,
		publicKey:  pubBytes,
		privateKey: privBytes,
	}
	return nil
}

func (m *MemoryKeyStore) GetMLKEMPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	if k.keyType != KeyTypeMLKEM {
		return nil, fmt.Errorf("key %s is not ML-KEM type", keyID)
	}
	result := make([]byte, len(k.publicKey))
	copy(result, k.publicKey)
	return result, nil
}

func (m *MemoryKeyStore) GetMLDSAPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	if k.keyType != KeyTypeMLDSA {
		return nil, fmt.Errorf("key %s is not ML-DSA type", keyID)
	}
	result := make([]byte, len(k.publicKey))
	copy(result, k.publicKey)
	return result, nil
}

func (m *MemoryKeyStore) DecapsulateMLKEM(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	if k.keyType != KeyTypeMLKEM {
		return nil, fmt.Errorf("key %s is not ML-KEM type", keyID)
	}

	return mlkem.DecapsulateFromBytes(k.privateKey, ciphertext)
}

func (m *MemoryKeyStore) SignMLDSA(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	if k.keyType != KeyTypeMLDSA {
		return nil, fmt.Errorf("key %s is not ML-DSA type", keyID)
	}

	return mldsa.SignFromBytes(k.privateKey, message)
}

func (m *MemoryKeyStore) VerifyMLDSA(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k, ok := m.keys[keyID]
	if !ok {
		return false, fmt.Errorf("key not found: %s", keyID)
	}
	if k.keyType != KeyTypeMLDSA {
		return false, fmt.Errorf("key %s is not ML-DSA type", keyID)
	}

	return mldsa.VerifyFromBytes(k.publicKey, message, signature)
}

func (m *MemoryKeyStore) HasKey(ctx context.Context, keyID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.keys[keyID]
	return ok, nil
}

func (m *MemoryKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.keys))
	for k := range m.keys {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MemoryKeyStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Zero out all private keys
	for _, k := range m.keys {
		for i := range k.privateKey {
			k.privateKey[i] = 0
		}
	}
	m.keys = nil
	return nil
}
