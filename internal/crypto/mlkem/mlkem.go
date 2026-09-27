// Package mlkem provides ML-KEM-768 (FIPS 203) key encapsulation using Cloudflare CIRCL.
package mlkem

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// Algorithm is the algorithm identifier.
	Algorithm = "ML-KEM-768"
	// PublicKeySize is the size of a ML-KEM-768 public key.
	PublicKeySize = mlkem768.PublicKeySize
	// PrivateKeySize is the size of a ML-KEM-768 private key.
	PrivateKeySize = mlkem768.PrivateKeySize
	// CiphertextSize is the size of the KEM ciphertext.
	CiphertextSize = mlkem768.CiphertextSize
	// SharedSecretSize is the size of the shared secret.
	SharedSecretSize = mlkem768.SharedKeySize
)

// KeyPair holds a ML-KEM-768 key pair.
type KeyPair struct {
	PublicKey  *mlkem768.PublicKey
	PrivateKey *mlkem768.PrivateKey
}

// GenerateKeyPair generates a new ML-KEM-768 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ML-KEM-768 keypair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// MarshalPublicKey serializes a public key to bytes.
func MarshalPublicKey(pk *mlkem768.PublicKey) ([]byte, error) {
	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling ML-KEM public key: %w", err)
	}
	return data, nil
}

// UnmarshalPublicKey deserializes a public key from bytes.
func UnmarshalPublicKey(data []byte) (*mlkem768.PublicKey, error) {
	pk := new(mlkem768.PublicKey)
	if err := pk.Unpack(data); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-KEM public key: %w", err)
	}
	return pk, nil
}

// MarshalPrivateKey serializes a private key to bytes.
func MarshalPrivateKey(sk *mlkem768.PrivateKey) ([]byte, error) {
	data, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling ML-KEM private key: %w", err)
	}
	return data, nil
}

// UnmarshalPrivateKey deserializes a private key from bytes.
func UnmarshalPrivateKey(data []byte) (*mlkem768.PrivateKey, error) {
	sk := new(mlkem768.PrivateKey)
	if err := sk.Unpack(data); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-KEM private key: %w", err)
	}
	return sk, nil
}

// Encapsulate performs ML-KEM-768 encapsulation against a public key.
// Returns (ciphertext, sharedSecret, error).
func Encapsulate(pk *mlkem768.PublicKey) (ciphertext, sharedSecret []byte, err error) {
	ct := make([]byte, CiphertextSize)
	ss := make([]byte, SharedSecretSize)

	seed := make([]byte, mlkem768.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("generating encapsulation seed: %w", err)
	}

	pk.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}

// EncapsulateFromBytes performs ML-KEM-768 encapsulation from serialized public key bytes.
func EncapsulateFromBytes(pkBytes []byte) (ciphertext, sharedSecret []byte, err error) {
	pk, err := UnmarshalPublicKey(pkBytes)
	if err != nil {
		return nil, nil, err
	}
	return Encapsulate(pk)
}

// Decapsulate performs ML-KEM-768 decapsulation using a private key.
// Returns the shared secret.
func Decapsulate(sk *mlkem768.PrivateKey, ciphertext []byte) ([]byte, error) {
	ss := make([]byte, SharedSecretSize)
	sk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}

// DecapsulateFromBytes performs ML-KEM-768 decapsulation from serialized private key bytes.
func DecapsulateFromBytes(skBytes, ciphertext []byte) ([]byte, error) {
	sk, err := UnmarshalPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	return Decapsulate(sk, ciphertext)
}
