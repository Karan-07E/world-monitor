// Package aesgcm provides AES-256-GCM encryption and decryption.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	// KeySize is the AES-256 key size in bytes.
	KeySize = 32
	// NonceSize is the standard GCM nonce size in bytes.
	NonceSize = 12
)

// GenerateKey generates a cryptographically random 256-bit AES key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating AES key: %w", err)
	}
	return key, nil
}

// GenerateNonce generates a cryptographically random GCM nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns (nonce, ciphertext, error). The ciphertext includes the GCM auth tag.
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// EncryptWithAAD encrypts plaintext with additional authenticated data.
func EncryptWithAAD(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts AES-256-GCM ciphertext.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), NonceSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// DecryptWithAAD decrypts AES-256-GCM ciphertext with additional authenticated data.
func DecryptWithAAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), NonceSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	return plaintext, nil
}

// WrapKey wraps a key using AES-256-GCM key wrapping.
func WrapKey(kek, keyToWrap []byte) (nonce, wrappedKey []byte, err error) {
	return Encrypt(kek, keyToWrap)
}

// UnwrapKey unwraps a key using AES-256-GCM.
func UnwrapKey(kek, nonce, wrappedKey []byte) ([]byte, error) {
	return Decrypt(kek, nonce, wrappedKey)
}

// Hash computes SHA-256 hash of data.
func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
