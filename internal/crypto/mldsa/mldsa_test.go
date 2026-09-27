package mldsa

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PublicKey == nil || kp.PrivateKey == nil {
		t.Fatal("nil keys")
	}
}

func TestSignVerify(t *testing.T) {
	kp, _ := GenerateKeyPair()
	message := []byte("test message for signing")

	sig, err := Sign(kp.PrivateKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), SignatureSize)
	}

	valid := Verify(kp.PublicKey, message, sig)
	if !valid {
		t.Fatal("valid signature rejected")
	}
}

func TestSignVerifyHashed(t *testing.T) {
	kp, _ := GenerateKeyPair()
	data := []byte("data to hash and sign")

	sig, err := SignHashed(kp.PrivateKey, data)
	if err != nil {
		t.Fatalf("SignHashed failed: %v", err)
	}

	valid := VerifyHashed(kp.PublicKey, data, sig)
	if !valid {
		t.Fatal("valid hashed signature rejected")
	}
}

func TestModifiedMessageFails(t *testing.T) {
	kp, _ := GenerateKeyPair()
	message := []byte("original message")

	sig, _ := Sign(kp.PrivateKey, message)

	modified := []byte("modified message")
	valid := Verify(kp.PublicKey, modified, sig)
	if valid {
		t.Fatal("modified message should fail verification")
	}
}

func TestWrongKeyFails(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	message := []byte("test message")

	sig, _ := Sign(kp1.PrivateKey, message)

	valid := Verify(kp2.PublicKey, message, sig)
	if valid {
		t.Fatal("wrong public key should fail verification")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	kp, _ := GenerateKeyPair()

	pubBytes, err := MarshalPublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	privBytes, err := MarshalPrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKey failed: %v", err)
	}

	pk, err := UnmarshalPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey failed: %v", err)
	}

	sk, err := UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKey failed: %v", err)
	}

	// Sign with deserialized key
	message := []byte("marshal test")
	sig, _ := Sign(sk, message)

	// Verify with deserialized key
	valid := Verify(pk, message, sig)
	if !valid {
		t.Fatal("signature verification failed after marshal/unmarshal")
	}
}

func TestFromBytes(t *testing.T) {
	kp, _ := GenerateKeyPair()
	message := sha256.Sum256([]byte("from bytes test"))

	skBytes, _ := MarshalPrivateKey(kp.PrivateKey)
	pkBytes, _ := MarshalPublicKey(kp.PublicKey)

	sig, err := SignFromBytes(skBytes, message[:])
	if err != nil {
		t.Fatalf("SignFromBytes failed: %v", err)
	}

	valid, err := VerifyFromBytes(pkBytes, message[:], sig)
	if err != nil {
		t.Fatalf("VerifyFromBytes failed: %v", err)
	}
	if !valid {
		t.Fatal("valid signature rejected")
	}
}

func TestKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	pk1, _ := MarshalPublicKey(kp1.PublicKey)
	pk2, _ := MarshalPublicKey(kp2.PublicKey)

	if bytes.Equal(pk1, pk2) {
		t.Fatal("key pairs should be unique")
	}
}
