package keystore

import (
	"context"
	"testing"

	"github.com/cryptoattr/secure-doc-dist/internal/crypto/mlkem"
)

func TestMemoryKeyStoreMLKEM(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	defer ks.Close()

	keyID := "test-kem-v1"

	if err := ks.GenerateMLKEMKeyPair(ctx, keyID); err != nil {
		t.Fatalf("GenerateMLKEMKeyPair failed: %v", err)
	}

	has, _ := ks.HasKey(ctx, keyID)
	if !has {
		t.Fatal("key should exist")
	}

	pubKey, err := ks.GetMLKEMPublicKey(ctx, keyID)
	if err != nil {
		t.Fatalf("GetMLKEMPublicKey failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("empty public key")
	}

	if err := ks.GenerateMLKEMKeyPair(ctx, keyID); err == nil {
		t.Fatal("duplicate key generation should fail")
	}
}

func TestMemoryKeyStoreMLDSA(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	defer ks.Close()

	keyID := "test-sign-v1"

	if err := ks.GenerateMLDSAKeyPair(ctx, keyID); err != nil {
		t.Fatalf("GenerateMLDSAKeyPair failed: %v", err)
	}

	pubKey, err := ks.GetMLDSAPublicKey(ctx, keyID)
	if err != nil {
		t.Fatalf("GetMLDSAPublicKey failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("empty public key")
	}

	message := []byte("test message")
	sig, err := ks.SignMLDSA(ctx, keyID, message)
	if err != nil {
		t.Fatalf("SignMLDSA failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	valid, err := ks.VerifyMLDSA(ctx, keyID, message, sig)
	if err != nil {
		t.Fatalf("VerifyMLDSA failed: %v", err)
	}
	if !valid {
		t.Fatal("valid signature rejected")
	}

	valid, _ = ks.VerifyMLDSA(ctx, keyID, []byte("wrong"), sig)
	if valid {
		t.Fatal("wrong message should fail verification")
	}
}

func TestMemoryKeyStoreEncapsDecaps(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	defer ks.Close()

	keyID := "test-kem-v1"
	if err := ks.GenerateMLKEMKeyPair(ctx, keyID); err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	pubKeyBytes, _ := ks.GetMLKEMPublicKey(ctx, keyID)

	// Encapsulate using mlkem package directly
	ct, ss, err := mlkem.EncapsulateFromBytes(pubKeyBytes)
	if err != nil {
		t.Fatalf("encapsulate failed: %v", err)
	}

	// Decapsulate through keystore
	ss2, err := ks.DecapsulateMLKEM(ctx, keyID, ct)
	if err != nil {
		t.Fatalf("DecapsulateMLKEM failed: %v", err)
	}

	if len(ss) != len(ss2) {
		t.Fatalf("shared secret lengths differ: %d vs %d", len(ss), len(ss2))
	}

	for i := range ss {
		if ss[i] != ss2[i] {
			t.Fatal("shared secrets do not match")
		}
	}
}

func TestListKeys(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	defer ks.Close()

	ks.GenerateMLKEMKeyPair(ctx, "k1")
	ks.GenerateMLDSAKeyPair(ctx, "k2")

	keys, err := ks.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestKeyNotFound(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	defer ks.Close()

	_, err := ks.GetMLKEMPublicKey(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}
