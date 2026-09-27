package aesgcm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key size = %d, want %d", len(key), KeySize)
	}

	// Ensure randomness
	key2, _ := GenerateKey()
	if bytes.Equal(key, key2) {
		t.Fatal("two generated keys are identical")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("The quick brown fox jumps over the lazy dog. Sensitive document content.")

	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(nonce), NonceSize)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted text does not match plaintext")
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	key, _ := GenerateKey()

	// 1MB of random data
	plaintext := make([]byte, 1<<20)
	rand.Read(plaintext)

	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted data does not match")
	}
}

func TestTamperDetection(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("tamper test data")

	nonce, ciphertext, _ := Encrypt(key, plaintext)

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err := Decrypt(key, nonce, tampered)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext")
	}
}

func TestWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	plaintext := []byte("wrong key test")

	nonce, ciphertext, _ := Encrypt(key1, plaintext)

	_, err := Decrypt(key2, nonce, ciphertext)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := make([]byte, 16)
	_, _, err := Encrypt(shortKey, []byte("test"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestKeyWrapUnwrap(t *testing.T) {
	kek, _ := GenerateKey()
	docKey, _ := GenerateKey()

	nonce, wrapped, err := WrapKey(kek, docKey)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	unwrapped, err := UnwrapKey(kek, nonce, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey failed: %v", err)
	}

	if !bytes.Equal(unwrapped, docKey) {
		t.Fatal("unwrapped key does not match original")
	}
}

func TestEncryptDecryptWithAAD(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("AAD protected data")
	aad := []byte("additional context info")

	nonce, ciphertext, err := EncryptWithAAD(key, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	decrypted, err := DecryptWithAAD(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted does not match plaintext")
	}

	// Wrong AAD should fail
	_, err = DecryptWithAAD(key, nonce, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Fatal("expected failure with wrong AAD")
	}
}
