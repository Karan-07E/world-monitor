package fabric

import (
	"context"
	"testing"
)

func TestMemoryLedgerRecipient(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	err := ledger.RegisterRecipient(ctx, "r1", "Test User", []byte("dsa-pub"), []byte("kem-pub"))
	if err != nil {
		t.Fatalf("RegisterRecipient failed: %v", err)
	}

	r, err := ledger.GetRecipient(ctx, "r1")
	if err != nil {
		t.Fatalf("GetRecipient failed: %v", err)
	}
	if r.RecipientID != "r1" {
		t.Fatalf("recipient ID = %s, want r1", r.RecipientID)
	}
	if r.DisplayName != "Test User" {
		t.Fatalf("display name = %s, want Test User", r.DisplayName)
	}
}

func TestMemoryLedgerRecipientNotFound(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	_, err := ledger.GetRecipient(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent recipient")
	}
}

func TestMemoryLedgerDocument(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	err := ledger.RegisterDocument(ctx, "doc1", "hash1", "test.pdf", []string{"r1", "r2"})
	if err != nil {
		t.Fatalf("RegisterDocument failed: %v", err)
	}
}

func TestMemoryLedgerDecryption(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	record := &LedgerRecord{
		EventID:      "event-001",
		DocumentID:   "doc-001",
		DocumentHash: "hash-001",
		RecipientID:  "recipient-001",
		WatermarkID:  "wm-001",
		SessionID:    "session-001",
		Timestamp:    "2024-01-01T00:00:00Z",
		Signature:    []byte("sig"),
	}

	txID, err := ledger.RecordDecryption(ctx, record)
	if err != nil {
		t.Fatalf("RecordDecryption failed: %v", err)
	}
	if txID == "" {
		t.Fatal("empty transaction ID")
	}

	// Retrieve by event ID
	retrieved, err := ledger.GetDecryptionRecord(ctx, "event-001")
	if err != nil {
		t.Fatalf("GetDecryptionRecord failed: %v", err)
	}
	if retrieved.EventID != "event-001" {
		t.Fatalf("event ID = %s, want event-001", retrieved.EventID)
	}
}

func TestMemoryLedgerWatermarkLookup(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	record := &LedgerRecord{
		EventID:      "event-001",
		DocumentID:   "doc-001",
		DocumentHash: "hash-001",
		RecipientID:  "recipient-001",
		WatermarkID:  "wm-001",
		SessionID:    "session-001",
	}

	ledger.RecordDecryption(ctx, record)

	// Lookup by watermark ID
	retrieved, err := ledger.GetByWatermarkID(ctx, "wm-001")
	if err != nil {
		t.Fatalf("GetByWatermarkID failed: %v", err)
	}
	if retrieved.RecipientID != "recipient-001" {
		t.Fatalf("recipient = %s, want recipient-001", retrieved.RecipientID)
	}
}

func TestMemoryLedgerDuplicateWatermark(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	record1 := &LedgerRecord{
		EventID:     "event-001",
		DocumentID:  "doc-001",
		WatermarkID: "wm-001",
		SessionID:   "session-001",
	}
	record2 := &LedgerRecord{
		EventID:     "event-002",
		DocumentID:  "doc-001",
		WatermarkID: "wm-001", // duplicate
		SessionID:   "session-002",
	}

	_, err := ledger.RecordDecryption(ctx, record1)
	if err != nil {
		t.Fatalf("first record failed: %v", err)
	}

	_, err = ledger.RecordDecryption(ctx, record2)
	if err == nil {
		t.Fatal("duplicate watermark ID should be rejected")
	}
}

func TestMemoryLedgerDuplicateEvent(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	record := &LedgerRecord{
		EventID:     "event-001",
		DocumentID:  "doc-001",
		WatermarkID: "wm-001",
		SessionID:   "session-001",
	}

	ledger.RecordDecryption(ctx, record)

	record2 := &LedgerRecord{
		EventID:     "event-001", // duplicate
		DocumentID:  "doc-001",
		WatermarkID: "wm-002",
		SessionID:   "session-002",
	}

	_, err := ledger.RecordDecryption(ctx, record2)
	if err == nil {
		t.Fatal("duplicate event ID should be rejected")
	}
}

func TestMemoryLedgerMalformedRecord(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	// Missing required fields
	record := &LedgerRecord{}
	_, err := ledger.RecordDecryption(ctx, record)
	if err == nil {
		t.Fatal("malformed record should be rejected")
	}
}

func TestMemoryLedgerDocumentHistory(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	ledger.RecordDecryption(ctx, &LedgerRecord{
		EventID: "e1", DocumentID: "doc1", WatermarkID: "wm1", SessionID: "s1",
	})
	ledger.RecordDecryption(ctx, &LedgerRecord{
		EventID: "e2", DocumentID: "doc1", WatermarkID: "wm2", SessionID: "s2",
	})
	ledger.RecordDecryption(ctx, &LedgerRecord{
		EventID: "e3", DocumentID: "doc2", WatermarkID: "wm3", SessionID: "s3",
	})

	history, err := ledger.GetDocumentHistory(ctx, "doc1")
	if err != nil {
		t.Fatalf("GetDocumentHistory failed: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 events for doc1, got %d", len(history))
	}
}

func TestMemoryLedgerAppendOnly(t *testing.T) {
	ledger := NewMemoryLedger()
	ctx := context.Background()

	// Record decryption
	record := &LedgerRecord{
		EventID:     "event-001",
		DocumentID:  "doc-001",
		WatermarkID: "wm-001",
		SessionID:   "session-001",
		RecipientID: "recipient-001",
	}

	ledger.RecordDecryption(ctx, record)

	// Try to overwrite - should fail (same event ID)
	record.RecipientID = "attacker"
	_, err := ledger.RecordDecryption(ctx, record)
	if err == nil {
		t.Fatal("should not be able to overwrite existing record")
	}

	// Verify original remains
	retrieved, _ := ledger.GetDecryptionRecord(ctx, "event-001")
	if retrieved.RecipientID != "recipient-001" {
		t.Fatal("original record was modified")
	}
}
