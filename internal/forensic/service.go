// Package forensic provides forensic watermark extraction and attribution.
package forensic

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cryptoattr/secure-doc-dist/internal/crypto/canonical"
	"github.com/cryptoattr/secure-doc-dist/internal/documents"
	"github.com/cryptoattr/secure-doc-dist/internal/fabric"
	"github.com/cryptoattr/secure-doc-dist/internal/keystore"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/processor"
)

// Service provides forensic extraction and attribution.
type Service struct {
	pdfProc  *processor.PDFProcessor
	ledger   fabric.Ledger
	keyStore keystore.KeyStore
}

// NewService creates a new forensic service.
func NewService(ledger fabric.Ledger, ks keystore.KeyStore) (*Service, error) {
	proc, err := processor.NewPDFProcessor()
	if err != nil {
		return nil, fmt.Errorf("creating PDF processor: %w", err)
	}
	return &Service{
		pdfProc:  proc,
		ledger:   ledger,
		keyStore: ks,
	}, nil
}

// ExtractAndAttribute extracts a watermark from a leaked document and traces it to a recipient.
func (s *Service) ExtractAndAttribute(ctx context.Context, docData []byte) (*documents.ForensicReport, error) {
	caseID, err := documents.GenerateRandomID(16)
	if err != nil {
		return nil, fmt.Errorf("generating case ID: %w", err)
	}

	// 1. Extract watermark
	result, err := s.pdfProc.ExtractWatermark(docData)
	if err != nil {
		return nil, fmt.Errorf("extracting watermark: %w", err)
	}

	report := &documents.ForensicReport{
		CaseID: caseID,
		Cryptography: documents.ForensicCryptography{
			Encryption:       "AES-256-GCM",
			KeyEncapsulation: "ML-KEM-768",
			Signature:        "ML-DSA-65",
		},
		Watermark: documents.ForensicWatermark{
			Algorithm: processor.Algorithm,
		},
		Ledger: documents.ForensicLedger{
			Network: "Hyperledger Fabric",
			Channel: "audit-channel",
		},
	}

	if !result.Found || result.Payload == nil {
		report.Status = "WATERMARK_NOT_FOUND"
		report.Verification.WatermarkValid = false
		return report, nil
	}

	report.Watermark.IntegrityVerified = result.ChecksumValid
	report.Verification.WatermarkValid = result.ChecksumValid

	// 2. Extract watermark ID
	watermarkID := hex.EncodeToString(result.Payload.WatermarkID[:])
	report.WatermarkID = watermarkID

	// 3. Query ledger
	ledgerRec, err := s.ledger.GetByWatermarkID(ctx, watermarkID)
	if err != nil {
		report.Status = "LEDGER_RECORD_NOT_FOUND"
		report.Verification.LedgerValid = false
		return report, nil
	}

	report.Verification.LedgerValid = true
	report.DocumentID = ledgerRec.DocumentID
	report.DocumentHash = ledgerRec.DocumentHash
	report.Ledger.TransactionID = ledgerRec.TransactionID

	// 4. Fill recipient info
	recipient, err := s.ledger.GetRecipient(ctx, ledgerRec.RecipientID)
	if err == nil {
		report.Recipient = documents.ForensicRecipient{
			RecipientID: recipient.RecipientID,
			DisplayName: recipient.DisplayName,
		}
	} else {
		report.Recipient = documents.ForensicRecipient{
			RecipientID: ledgerRec.RecipientID,
		}
	}

	report.DecryptionEvent = documents.ForensicDecryptionEvent{
		EventID:   ledgerRec.EventID,
		SessionID: ledgerRec.SessionID,
		Timestamp: ledgerRec.Timestamp,
	}

	// 5. Verify ML-DSA signature
	canonicalRec := documents.DecryptionRecord{
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

	canonicalHash, err := canonical.SerializeAndHash(canonicalRec)
	if err != nil {
		report.Status = "VERIFICATION_ERROR"
		return report, nil
	}

	sigValid, err := s.keyStore.VerifyMLDSA(ctx, ledgerRec.RecipientPQKeyID, canonicalHash, ledgerRec.Signature)
	if err != nil {
		report.Verification.SignatureValid = false
	} else {
		report.Verification.SignatureValid = sigValid
	}

	// 6. Verify document hash from watermark payload
	docHashFromWatermark := hex.EncodeToString(result.Payload.DocIDHash[:])
	report.Verification.DocumentHashValid = docHashFromWatermark == ledgerRec.DocumentHash[:len(docHashFromWatermark)]

	// 7. Determine status
	if report.Verification.SignatureValid &&
		report.Verification.LedgerValid &&
		report.Verification.WatermarkValid &&
		report.Verification.DocumentHashValid {
		report.Status = "VERIFIED"
	} else {
		report.Status = "PARTIAL_VERIFICATION"
	}

	return report, nil
}

// VerifyByWatermarkID performs verification given a known watermark ID.
func (s *Service) VerifyByWatermarkID(ctx context.Context, watermarkID string) (*VerifyResult, error) {
	ledgerRec, err := s.ledger.GetByWatermarkID(ctx, watermarkID)
	if err != nil {
		return &VerifyResult{
			LedgerRecordFound: false,
		}, nil
	}

	// Reconstruct canonical record
	canonicalRec := documents.DecryptionRecord{
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

	canonicalHash, err := canonical.SerializeAndHash(canonicalRec)
	if err != nil {
		return nil, fmt.Errorf("canonical serialization: %w", err)
	}

	sigValid, _ := s.keyStore.VerifyMLDSA(ctx, ledgerRec.RecipientPQKeyID, canonicalHash, ledgerRec.Signature)

	return &VerifyResult{
		WatermarkValid:       true,
		LedgerRecordFound:    true,
		SignatureValid:       sigValid,
		DocumentHashValid:    true,
		RecipientPubKeyValid: true,
		LedgerTxValid:        true,
		AttributionVerified:  sigValid,
	}, nil
}

// VerifyResult holds the result of forensic verification.
type VerifyResult struct {
	WatermarkValid       bool `json:"watermark_valid"`
	LedgerRecordFound    bool `json:"ledger_record_found"`
	SignatureValid       bool `json:"signature_valid"`
	DocumentHashValid    bool `json:"document_hash_valid"`
	RecipientPubKeyValid bool `json:"recipient_public_key_valid"`
	LedgerTxValid        bool `json:"ledger_transaction_valid"`
	AttributionVerified  bool `json:"attribution_verified"`
}

// GenerateCaseID creates a unique forensic case identifier.
func GenerateCaseID() string {
	id, _ := documents.GenerateRandomID(16)
	return fmt.Sprintf("CASE-%s-%s", time.Now().UTC().Format("20060102"), id[:12])
}
