// Package provenance provides the provenance service that orchestrates decryption,
// watermarking, signing, and ledger recording.
package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cryptoattr/secure-doc-dist/internal/crypto/canonical"
	"github.com/cryptoattr/secure-doc-dist/internal/documents"
	"github.com/cryptoattr/secure-doc-dist/internal/fabric"
	"github.com/cryptoattr/secure-doc-dist/internal/keystore"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/payload"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/processor"
)

// Service orchestrates the complete decryption → watermark → sign → ledger flow.
type Service struct {
	docService *documents.Service
	keyStore   keystore.KeyStore
	ledger     fabric.Ledger
	pdfProc    *processor.PDFProcessor
}

// DecryptionOutput holds the result of a successful decryption with provenance.
type DecryptionOutput struct {
	WatermarkedDoc  []byte
	EventID         string
	SessionID       string
	WatermarkID     string
	TransactionID   string
	DocumentID      string
	RecipientID     string
	Signature       []byte
}

// NewService creates a new provenance service.
func NewService(docSvc *documents.Service, ks keystore.KeyStore, ledger fabric.Ledger) (*Service, error) {
	pdfProc, err := processor.NewPDFProcessor()
	if err != nil {
		return nil, fmt.Errorf("creating PDF processor: %w", err)
	}
	return &Service{
		docService: docSvc,
		keyStore:   ks,
		ledger:     ledger,
		pdfProc:    pdfProc,
	}, nil
}

// DecryptWithProvenance performs the complete decryption flow with watermarking and audit.
func (s *Service) DecryptWithProvenance(ctx context.Context, documentID, recipientID string) (*DecryptionOutput, error) {
	// 1. Decrypt document
	plaintext, pkg, err := s.docService.DecryptForRecipient(ctx, documentID, recipientID)
	if err != nil {
		return nil, fmt.Errorf("decrypting document: %w", err)
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	// 2. Generate unique IDs
	eventID, err := documents.GenerateRandomID(32)
	if err != nil {
		return nil, fmt.Errorf("generating event ID: %w", err)
	}

	sessionID, err := documents.GenerateRandomID(32)
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	watermarkID, err := documents.GenerateRandomID(32)
	if err != nil {
		return nil, fmt.Errorf("generating watermark ID: %w", err)
	}

	// 3. Build watermark payload
	docHashBytes, _ := hex.DecodeString(pkg.DocumentSHA256)
	sessionIDBytes, _ := hex.DecodeString(sessionID)
	watermarkIDBytes, _ := hex.DecodeString(watermarkID)

	wp, err := payload.NewPayload(docHashBytes, sessionIDBytes, watermarkIDBytes)
	if err != nil {
		return nil, fmt.Errorf("creating watermark payload: %w", err)
	}

	// 4. Embed watermark
	watermarkedPDF, err := s.pdfProc.EmbedWatermark(plaintext, wp)
	if err != nil {
		return nil, fmt.Errorf("embedding watermark: %w", err)
	}

	// 5. Build canonical decryption record
	payloadHash := wp.Hash()
	dsaKeyID := recipientID + "-sign-v1"

	record := documents.DecryptionRecord{
		RecordVersion:        "1",
		EventID:              eventID,
		DocumentID:           documentID,
		DocumentHash:         pkg.DocumentSHA256,
		RecipientID:          recipientID,
		RecipientPQKeyID:     dsaKeyID,
		SessionID:            sessionID,
		WatermarkID:          watermarkID,
		WatermarkPayloadHash: hex.EncodeToString(payloadHash),
		TimestampUTC:         time.Now().UTC().Format(time.RFC3339Nano),
		WatermarkAlgorithm:   processor.Algorithm,
		SignatureAlgorithm:   "ML-DSA-65",
	}

	// 6. Canonical serialization and hash
	canonicalHash, err := canonical.SerializeAndHash(record)
	if err != nil {
		return nil, fmt.Errorf("canonical serialization: %w", err)
	}

	// 7. Sign with ML-DSA-65
	signature, err := s.keyStore.SignMLDSA(ctx, dsaKeyID, canonicalHash)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing: %w", err)
	}

	// 8. Get public key for ledger
	dsaPubKey, err := s.keyStore.GetMLDSAPublicKey(ctx, dsaKeyID)
	if err != nil {
		return nil, fmt.Errorf("getting DSA public key: %w", err)
	}

	// 9. Submit to ledger
	ledgerRecord := &fabric.LedgerRecord{
		EventID:              eventID,
		DocumentID:           documentID,
		DocumentHash:         pkg.DocumentSHA256,
		RecipientID:          recipientID,
		WatermarkID:          watermarkID,
		SessionID:            sessionID,
		Timestamp:            record.TimestampUTC,
		Signature:            signature,
		RecipientMLDSAPubKey: dsaPubKey,
		SignatureAlgorithm:   "ML-DSA-65",
		WatermarkAlgorithm:   processor.Algorithm,
		WatermarkPayloadHash: record.WatermarkPayloadHash,
		RecipientPQKeyID:     dsaKeyID,
		RecordVersion:        "1",
	}

	txID, err := s.ledger.RecordDecryption(ctx, ledgerRecord)
	if err != nil {
		return nil, fmt.Errorf("recording decryption on ledger: %w", err)
	}

	// 10. Only after ledger commit, return the watermarked document
	return &DecryptionOutput{
		WatermarkedDoc: watermarkedPDF,
		EventID:        eventID,
		SessionID:      sessionID,
		WatermarkID:    watermarkID,
		TransactionID:  txID,
		DocumentID:     documentID,
		RecipientID:    recipientID,
		Signature:      signature,
	}, nil
}

// VerifyDecryptionRecord verifies a decryption record's ML-DSA signature.
func (s *Service) VerifyDecryptionRecord(ctx context.Context, eventID string) (*VerificationResult, error) {
	// 1. Get record from ledger
	ledgerRec, err := s.ledger.GetDecryptionRecord(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("getting ledger record: %w", err)
	}

	// 2. Reconstruct canonical record
	record := documents.DecryptionRecord{
		RecordVersion:        ledgerRec.RecordVersion,
		EventID:              ledgerRec.EventID,
		DocumentID:           ledgerRec.DocumentID,
		DocumentHash:         ledgerRec.DocumentHash,
		RecipientID:          ledgerRec.RecipientID,
		RecipientPQKeyID:     ledgerRec.RecipientPQKeyID,
		SessionID:            ledgerRec.SessionID,
		WatermarkID:          ledgerRec.WatermarkID,
		WatermarkPayloadHash: ledgerRec.WatermarkPayloadHash,
		TimestampUTC:         ledgerRec.Timestamp,
		WatermarkAlgorithm:   ledgerRec.WatermarkAlgorithm,
		SignatureAlgorithm:   ledgerRec.SignatureAlgorithm,
	}

	// 3. Canonical hash
	canonicalHash, err := canonical.SerializeAndHash(record)
	if err != nil {
		return nil, fmt.Errorf("canonical serialization: %w", err)
	}

	// 4. Verify ML-DSA signature using stored public key
	sigValid, err := s.keyStore.VerifyMLDSA(ctx, ledgerRec.RecipientPQKeyID, canonicalHash, ledgerRec.Signature)
	if err != nil {
		// Try with ledger-stored public key directly
		sigValid = false
	}

	return &VerificationResult{
		SignatureValid:    sigValid,
		LedgerRecordFound: true,
		DocumentHash:      ledgerRec.DocumentHash,
		RecipientID:       ledgerRec.RecipientID,
		EventID:           ledgerRec.EventID,
		WatermarkID:       ledgerRec.WatermarkID,
		TransactionID:     ledgerRec.TransactionID,
	}, nil
}

// VerificationResult holds the result of record verification.
type VerificationResult struct {
	SignatureValid     bool   `json:"signature_valid"`
	LedgerRecordFound bool   `json:"ledger_record_found"`
	DocumentHash       string `json:"document_hash"`
	RecipientID        string `json:"recipient_id"`
	EventID            string `json:"event_id"`
	WatermarkID        string `json:"watermark_id"`
	TransactionID      string `json:"transaction_id"`
}

// GetWatermarkIDHash computes SHA-256 of a watermark ID for lookup.
func GetWatermarkIDHash(watermarkID string) string {
	h := sha256.Sum256([]byte(watermarkID))
	return hex.EncodeToString(h[:])
}
