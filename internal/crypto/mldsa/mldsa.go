// Package mldsa provides ML-DSA-65 (FIPS 204) digital signatures using Cloudflare CIRCL.
package mldsa

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	// Algorithm is the algorithm identifier.
	Algorithm = "ML-DSA-65"
	// PublicKeySize is the size of an ML-DSA-65 public key.
	PublicKeySize = mldsa65.PublicKeySize
	// PrivateKeySize is the size of an ML-DSA-65 private key.
	PrivateKeySize = mldsa65.PrivateKeySize
	// SignatureSize is the size of an ML-DSA-65 signature.
	SignatureSize = mldsa65.SignatureSize
)

// KeyPair holds an ML-DSA-65 key pair.
type KeyPair struct {
	PublicKey  *mldsa65.PublicKey
	PrivateKey *mldsa65.PrivateKey
}

// GenerateKeyPair generates a new ML-DSA-65 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ML-DSA-65 keypair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// MarshalPublicKey serializes a public key to bytes.
func MarshalPublicKey(pk *mldsa65.PublicKey) ([]byte, error) {
	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling ML-DSA public key: %w", err)
	}
	return data, nil
}

// UnmarshalPublicKey deserializes a public key from bytes.
func UnmarshalPublicKey(data []byte) (*mldsa65.PublicKey, error) {
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-DSA public key: %w", err)
	}
	return pk, nil
}

// MarshalPrivateKey serializes a private key to bytes.
func MarshalPrivateKey(sk *mldsa65.PrivateKey) ([]byte, error) {
	data, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling ML-DSA private key: %w", err)
	}
	return data, nil
}

// UnmarshalPrivateKey deserializes a private key from bytes.
func UnmarshalPrivateKey(data []byte) (*mldsa65.PrivateKey, error) {
	sk := new(mldsa65.PrivateKey)
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("unmarshaling ML-DSA private key: %w", err)
	}
	return sk, nil
}

// Sign signs a message using ML-DSA-65.
func Sign(sk *mldsa65.PrivateKey, message []byte) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	// SignTo(sk, msg, ctx, randomized, sig)
	// ctx is nil for standard signing, randomized=false for deterministic
	if err := mldsa65.SignTo(sk, message, nil, false, signature); err != nil {
		return nil, fmt.Errorf("ML-DSA signing: %w", err)
	}
	return signature, nil
}

// SignHashed signs the SHA-256 hash of data using ML-DSA-65.
func SignHashed(sk *mldsa65.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return Sign(sk, hash[:])
}

// SignFromBytes signs a message using serialized private key bytes.
func SignFromBytes(skBytes, message []byte) ([]byte, error) {
	sk, err := UnmarshalPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	return Sign(sk, message)
}

// Verify verifies an ML-DSA-65 signature.
func Verify(pk *mldsa65.PublicKey, message, signature []byte) bool {
	return mldsa65.Verify(pk, message, nil, signature)
}

// VerifyHashed verifies a signature against the SHA-256 hash of data.
func VerifyHashed(pk *mldsa65.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)
	return Verify(pk, hash[:], signature)
}

// VerifyFromBytes verifies using serialized public key bytes.
func VerifyFromBytes(pkBytes, message, signature []byte) (bool, error) {
	pk, err := UnmarshalPublicKey(pkBytes)
	if err != nil {
		return false, err
	}
	return Verify(pk, message, signature), nil
}
