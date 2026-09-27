// Package fabric provides the Hyperledger Fabric ledger client.
package fabric

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// LedgerRecord represents a decryption record stored on the Fabric ledger.
type LedgerRecord struct {
	EventID                string `json:"event_id"`
	DocumentID             string `json:"document_id"`
	DocumentHash           string `json:"document_hash"`
	RecipientID            string `json:"recipient_id"`
	WatermarkID            string `json:"watermark_id"`
	SessionID              string `json:"session_id"`
	Timestamp              string `json:"timestamp"`
	Signature              []byte `json:"signature"`
	RecipientMLDSAPubKey   []byte `json:"recipient_mldsa_public_key"`
	SignatureAlgorithm     string `json:"signature_algorithm"`
	WatermarkAlgorithm     string `json:"watermark_algorithm"`
	WatermarkPayloadHash   string `json:"watermark_payload_hash"`
	RecipientPQKeyID       string `json:"recipient_pq_key_id"`
	TransactionID          string `json:"transaction_id"`
	RecordVersion          string `json:"record_version"`
}

// Ledger defines the interface for the immutable audit ledger.
type Ledger interface {
	// RegisterRecipient registers a recipient's PQ identity on the ledger.
	RegisterRecipient(ctx context.Context, recipientID, displayName string, dsaPubKey []byte, kemPubKey []byte) error

	// GetRecipient retrieves a registered recipient.
	GetRecipient(ctx context.Context, recipientID string) (*RecipientRecord, error)

	// RegisterDocument registers a document on the ledger.
	RegisterDocument(ctx context.Context, documentID, documentHash, filename string, recipientIDs []string) error

	// RecordDecryption commits a signed decryption record to the ledger.
	RecordDecryption(ctx context.Context, record *LedgerRecord) (transactionID string, err error)

	// GetDecryptionRecord retrieves a decryption record by event ID.
	GetDecryptionRecord(ctx context.Context, eventID string) (*LedgerRecord, error)

	// GetByWatermarkID retrieves a decryption record by watermark ID.
	GetByWatermarkID(ctx context.Context, watermarkID string) (*LedgerRecord, error)

	// GetDocumentHistory returns all decryption records for a document.
	GetDocumentHistory(ctx context.Context, documentID string) ([]*LedgerRecord, error)

	// Close releases resources.
	Close() error
}

// RecipientRecord represents a registered recipient on the ledger.
type RecipientRecord struct {
	RecipientID  string `json:"recipient_id"`
	DisplayName  string `json:"display_name"`
	DSAPubKey    []byte `json:"dsa_public_key"`
	KEMPubKey    []byte `json:"kem_public_key"`
	RegisteredAt string `json:"registered_at"`
}

// MemoryLedger implements the Ledger interface with in-memory storage.
// Used when Fabric is not available. Provides the same append-only semantics.
type MemoryLedger struct {
	mu               sync.RWMutex
	recipients       map[string]*RecipientRecord
	documents        map[string]*DocumentRecord
	decryptionEvents map[string]*LedgerRecord // keyed by event ID
	watermarkIndex   map[string]string        // watermark ID -> event ID
	docHistory       map[string][]string      // document ID -> []event IDs
	txCounter        int
}

// DocumentRecord represents a registered document.
type DocumentRecord struct {
	DocumentID   string   `json:"document_id"`
	DocumentHash string   `json:"document_hash"`
	Filename     string   `json:"filename"`
	RecipientIDs []string `json:"recipient_ids"`
	RegisteredAt string   `json:"registered_at"`
}

// NewMemoryLedger creates a new in-memory ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{
		recipients:       make(map[string]*RecipientRecord),
		documents:        make(map[string]*DocumentRecord),
		decryptionEvents: make(map[string]*LedgerRecord),
		watermarkIndex:   make(map[string]string),
		docHistory:       make(map[string][]string),
	}
}

func (m *MemoryLedger) RegisterRecipient(ctx context.Context, recipientID, displayName string, dsaPubKey, kemPubKey []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recipients[recipientID] = &RecipientRecord{
		RecipientID:  recipientID,
		DisplayName:  displayName,
		DSAPubKey:    dsaPubKey,
		KEMPubKey:    kemPubKey,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}
	return nil
}

func (m *MemoryLedger) GetRecipient(ctx context.Context, recipientID string) (*RecipientRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	r, ok := m.recipients[recipientID]
	if !ok {
		return nil, fmt.Errorf("recipient not found: %s", recipientID)
	}
	return r, nil
}

func (m *MemoryLedger) RegisterDocument(ctx context.Context, documentID, documentHash, filename string, recipientIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.documents[documentID] = &DocumentRecord{
		DocumentID:   documentID,
		DocumentHash: documentHash,
		Filename:     filename,
		RecipientIDs: recipientIDs,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}
	return nil
}

func (m *MemoryLedger) RecordDecryption(ctx context.Context, record *LedgerRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate record
	if record.EventID == "" || record.WatermarkID == "" || record.DocumentID == "" {
		return "", fmt.Errorf("malformed record: missing required fields")
	}

	// Check duplicate watermark ID
	if _, exists := m.watermarkIndex[record.WatermarkID]; exists {
		return "", fmt.Errorf("duplicate watermark ID: %s", record.WatermarkID)
	}

	// Check duplicate event ID
	if _, exists := m.decryptionEvents[record.EventID]; exists {
		return "", fmt.Errorf("duplicate event ID: %s", record.EventID)
	}

	// Generate transaction ID
	m.txCounter++
	txID := fmt.Sprintf("tx-%06d-%s", m.txCounter, record.EventID[:8])
	record.TransactionID = txID

	// Store (immutable - cannot be updated)
	recordCopy := *record
	m.decryptionEvents[record.EventID] = &recordCopy
	m.watermarkIndex[record.WatermarkID] = record.EventID
	m.docHistory[record.DocumentID] = append(m.docHistory[record.DocumentID], record.EventID)

	return txID, nil
}

func (m *MemoryLedger) GetDecryptionRecord(ctx context.Context, eventID string) (*LedgerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	r, ok := m.decryptionEvents[eventID]
	if !ok {
		return nil, fmt.Errorf("decryption record not found: %s", eventID)
	}
	return r, nil
}

func (m *MemoryLedger) GetByWatermarkID(ctx context.Context, watermarkID string) (*LedgerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventID, ok := m.watermarkIndex[watermarkID]
	if !ok {
		return nil, fmt.Errorf("watermark ID not found: %s", watermarkID)
	}

	r, ok := m.decryptionEvents[eventID]
	if !ok {
		return nil, fmt.Errorf("decryption record not found for watermark: %s", watermarkID)
	}
	return r, nil
}

func (m *MemoryLedger) GetDocumentHistory(ctx context.Context, documentID string) ([]*LedgerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eventIDs, ok := m.docHistory[documentID]
	if !ok {
		return nil, nil
	}

	records := make([]*LedgerRecord, 0, len(eventIDs))
	for _, eid := range eventIDs {
		if r, ok := m.decryptionEvents[eid]; ok {
			records = append(records, r)
		}
	}
	return records, nil
}

func (m *MemoryLedger) Close() error {
	return nil
}

// MarshalRecord serializes a LedgerRecord to JSON.
func MarshalRecord(r *LedgerRecord) ([]byte, error) {
	return json.Marshal(r)
}

// UnmarshalRecord deserializes a LedgerRecord from JSON.
func UnmarshalRecord(data []byte) (*LedgerRecord, error) {
	r := &LedgerRecord{}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}
