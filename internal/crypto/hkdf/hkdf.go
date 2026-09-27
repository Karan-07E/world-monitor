// Package hkdf provides HKDF-SHA-256 key derivation.
package hkdf

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// DefaultKeySize is the default derived key size in bytes (256-bit).
	DefaultKeySize = 32
)

// DeriveKey derives a key using HKDF-SHA-256.
// sharedSecret: the input keying material (IKM)
// salt: optional salt value (can be nil for no salt)
// info: context and application specific information
// keyLen: length of output key in bytes
func DeriveKey(sharedSecret, salt []byte, info string, keyLen int) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("key length must be positive")
	}

	reader := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

// DeriveDocumentKeyWrapKey derives a KEK from a ML-KEM shared secret
// for wrapping the AES document key.
func DeriveDocumentKeyWrapKey(sharedSecret, salt []byte) ([]byte, error) {
	return DeriveKey(sharedSecret, salt, "document-key-wrap-v1", DefaultKeySize)
}
