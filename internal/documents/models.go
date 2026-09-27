// Package documents defines document models and the encryption/decryption service.
package documents

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// EncryptedDocumentPackage represents a fully encrypted document with per-recipient key envelopes.
type EncryptedDocumentPackage struct {
	PackageID            string               `json:"package_id"`
	DocumentID           string               `json:"document_id"`
	OriginalFilename     string               `json:"original_filename"`
	DocumentSHA256       string               `json:"document_sha256"`
	AESGCMNonce          []byte               `json:"aesgcm_nonce"`
	EncryptedDocument    []byte               `json:"encrypted_document"`
	RecipientEnvelopes   []RecipientEnvelope   `json:"recipient_envelopes"`
	AlgorithmMetadata    AlgorithmMetadata     `json:"algorithm_metadata"`
	Version              string               `json:"version"`
	CreatedAt            time.Time             `json:"created_at"`
}

// RecipientEnvelope contains a recipient's wrapped key material.
type RecipientEnvelope struct {
	RecipientID     string `json:"recipient_id"`
	KEMAlgorithm    string `json:"kem_algorithm"`
	KEMCiphertext   []byte `json:"kem_ciphertext"`
	WrappedAESKey   []byte `json:"wrapped_aes_key"`
	WrapNonce       []byte `json:"wrap_nonce"`
	WrapSalt        []byte `json:"wrap_salt"`
	KEMKeyID        string `json:"kem_key_id"`
}

// AlgorithmMetadata describes the cryptographic algorithms used.
type AlgorithmMetadata struct {
	Encryption     string `json:"encryption"`
	KEM            string `json:"kem"`
	Signature      string `json:"signature"`
	KeyDerivation  string `json:"key_derivation"`
	Hash           string `json:"hash"`
}

// DefaultAlgorithms returns the default algorithm metadata.
func DefaultAlgorithms() AlgorithmMetadata {
	return AlgorithmMetadata{
		Encryption:    "AES-256-GCM",
		KEM:           "ML-KEM-768",
		Signature:     "ML-DSA-65",
		KeyDerivation: "HKDF-SHA-256",
		Hash:          "SHA-256",
	}
}

// Recipient represents a registered recipient.
type Recipient struct {
	RecipientID     string    `json:"recipient_id"`
	DisplayName     string    `json:"display_name"`
	KEMKeyID        string    `json:"kem_key_id"`
	DSAKeyID        string    `json:"dsa_key_id"`
	KEMPublicKey    []byte    `json:"kem_public_key,omitempty"`
	DSAPublicKey    []byte    `json:"dsa_public_key,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	Active          bool      `json:"active"`
}

// DecryptionRecord represents a canonical decryption event record.
type DecryptionRecord struct {
	RecordVersion        string `json:"record_version"`
	EventID              string `json:"event_id"`
	DocumentID           string `json:"document_id"`
	DocumentHash         string `json:"document_hash"`
	RecipientID          string `json:"recipient_id"`
	RecipientPQKeyID     string `json:"recipient_pq_key_id"`
	SessionID            string `json:"session_id"`
	WatermarkID          string `json:"watermark_id"`
	WatermarkPayloadHash string `json:"watermark_payload_hash"`
	TimestampUTC         string `json:"timestamp_utc"`
	WatermarkAlgorithm   string `json:"watermark_algorithm"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
}

// SignedDecryptionRecord wraps a DecryptionRecord with its ML-DSA signature.
type SignedDecryptionRecord struct {
	Record              DecryptionRecord `json:"record"`
	Signature           []byte           `json:"signature"`
	RecipientDSAKeyID   string           `json:"recipient_dsa_key_id"`
	RecipientDSAPubKey  []byte           `json:"recipient_dsa_public_key"`
	Algorithm           string           `json:"algorithm"`
}

// ForensicReport represents the output of forensic analysis.
type ForensicReport struct {
	CaseID          string                   `json:"case_id"`
	WatermarkID     string                   `json:"watermark_id"`
	DocumentID      string                   `json:"document_id"`
	DocumentHash    string                   `json:"document_hash"`
	Recipient       ForensicRecipient        `json:"recipient"`
	DecryptionEvent ForensicDecryptionEvent  `json:"decryption_event"`
	Cryptography    ForensicCryptography     `json:"cryptography"`
	Watermark       ForensicWatermark        `json:"watermark"`
	Ledger          ForensicLedger           `json:"ledger"`
	Verification    ForensicVerification     `json:"verification"`
	Status          string                   `json:"status"`
}

// ForensicRecipient identifies the attributed recipient.
type ForensicRecipient struct {
	RecipientID  string `json:"recipient_id"`
	DisplayName  string `json:"display_name"`
}

// ForensicDecryptionEvent describes the decryption event.
type ForensicDecryptionEvent struct {
	EventID    string `json:"event_id"`
	SessionID  string `json:"session_id"`
	Timestamp  string `json:"timestamp"`
}

// ForensicCryptography describes the cryptographic algorithms used.
type ForensicCryptography struct {
	Encryption       string `json:"encryption"`
	KeyEncapsulation string `json:"key_encapsulation"`
	Signature        string `json:"signature"`
}

// ForensicWatermark describes the watermark details.
type ForensicWatermark struct {
	Algorithm        string `json:"algorithm"`
	IntegrityVerified bool   `json:"integrity_verified"`
}

// ForensicLedger describes the ledger details.
type ForensicLedger struct {
	Network       string `json:"network"`
	Channel       string `json:"channel"`
	TransactionID string `json:"transaction_id"`
}

// ForensicVerification contains all verification statuses.
type ForensicVerification struct {
	SignatureValid    bool `json:"signature_valid"`
	LedgerValid       bool `json:"ledger_valid"`
	WatermarkValid    bool `json:"watermark_valid"`
	DocumentHashValid bool `json:"document_hash_valid"`
}

// GenerateRandomID generates a cryptographically random hex ID of the given byte length.
func GenerateRandomID(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating random ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ComputeSHA256 computes the SHA-256 hash of data and returns it as a hex string.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
