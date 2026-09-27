package mlkem

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PublicKey == nil || kp.PrivateKey == nil {
		t.Fatal("nil keys generated")
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, ss, err := Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	if len(ct) == 0 || len(ss) == 0 {
		t.Fatal("empty ciphertext or shared secret")
	}

	ss2, err := Decapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestMarshalUnmarshalPublicKey(t *testing.T) {
	kp, _ := GenerateKeyPair()

	data, err := MarshalPublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	pk, err := UnmarshalPublicKey(data)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey failed: %v", err)
	}

	// Test that the unmarshaled key works
	ct, ss, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate with unmarshaled key failed: %v", err)
	}

	ss2, err := Decapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match after marshal/unmarshal")
	}
}

func TestWrongKeyDecapsulation(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	ct, ss1, _ := Encapsulate(kp1.PublicKey)

	// Decapsulate with wrong key should produce different shared secret
	ss2, err := Decapsulate(kp2.PrivateKey, ct)
	if err != nil {
		// ML-KEM may not error but should produce different SS
		return
	}

	if bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets should differ with wrong private key")
	}
}

func TestEncapsulateFromBytes(t *testing.T) {
	kp, _ := GenerateKeyPair()

	pubBytes, _ := MarshalPublicKey(kp.PublicKey)
	ct, ss, err := EncapsulateFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("EncapsulateFromBytes failed: %v", err)
	}

	ss2, err := Decapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestDecapsulateFromBytes(t *testing.T) {
	kp, _ := GenerateKeyPair()

	ct, ss, _ := Encapsulate(kp.PublicKey)

	skBytes, _ := MarshalPrivateKey(kp.PrivateKey)
	ss2, err := DecapsulateFromBytes(skBytes, ct)
	if err != nil {
		t.Fatalf("DecapsulateFromBytes failed: %v", err)
	}

	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	pk1, _ := MarshalPublicKey(kp1.PublicKey)
	pk2, _ := MarshalPublicKey(kp2.PublicKey)

	if bytes.Equal(pk1, pk2) {
		t.Fatal("two key pairs should not be identical")
	}
}
