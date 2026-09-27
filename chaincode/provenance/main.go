// Package main implements the Hyperledger Fabric chaincode for provenance tracking.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ProvenanceChaincode implements the provenance tracking smart contract.
type ProvenanceChaincode struct {
	contractapi.Contract
}

// RecipientRecord represents a registered recipient on the ledger.
type RecipientRecord struct {
	DocType      string `json:"doc_type"`
	RecipientID  string `json:"recipient_id"`
	DisplayName  string `json:"display_name"`
	DSAPubKey    string `json:"dsa_public_key"`
	KEMPubKey    string `json:"kem_public_key"`
	RegisteredAt string `json:"registered_at"`
}

// DocumentRecord represents a registered document.
type DocumentRecord struct {
	DocType      string   `json:"doc_type"`
	DocumentID   string   `json:"document_id"`
	DocumentHash string   `json:"document_hash"`
	Filename     string   `json:"filename"`
	RecipientIDs []string `json:"recipient_ids"`
	RegisteredAt string   `json:"registered_at"`
}

// DecryptionRecord represents an immutable decryption event record.
type DecryptionRecord struct {
	DocType              string `json:"doc_type"`
	EventID              string `json:"event_id"`
	DocumentID           string `json:"document_id"`
	DocumentHash         string `json:"document_hash"`
	RecipientID          string `json:"recipient_id"`
	WatermarkID          string `json:"watermark_id"`
	SessionID            string `json:"session_id"`
	Timestamp            string `json:"timestamp"`
	Signature            string `json:"signature"`
	RecipientMLDSAPubKey string `json:"recipient_mldsa_public_key"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	WatermarkAlgorithm   string `json:"watermark_algorithm"`
	WatermarkPayloadHash string `json:"watermark_payload_hash"`
	RecipientPQKeyID     string `json:"recipient_pq_key_id"`
	RecordVersion        string `json:"record_version"`
	TransactionID        string `json:"transaction_id"`
}

// RegisterRecipient registers a new recipient on the ledger.
func (pc *ProvenanceChaincode) RegisterRecipient(ctx contractapi.TransactionContextInterface,
	recipientID, displayName, dsaPubKey, kemPubKey string) error {

	// Check if already exists
	existing, err := ctx.GetStub().GetState("recipient:" + recipientID)
	if err != nil {
		return fmt.Errorf("failed to read state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("recipient already registered: %s", recipientID)
	}

	record := RecipientRecord{
		DocType:      "recipient",
		RecipientID:  recipientID,
		DisplayName:  displayName,
		DSAPubKey:    dsaPubKey,
		KEMPubKey:    kemPubKey,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return ctx.GetStub().PutState("recipient:"+recipientID, data)
}

// GetRecipient retrieves a registered recipient.
func (pc *ProvenanceChaincode) GetRecipient(ctx contractapi.TransactionContextInterface,
	recipientID string) (*RecipientRecord, error) {

	data, err := ctx.GetStub().GetState("recipient:" + recipientID)
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("recipient not found: %s", recipientID)
	}

	record := &RecipientRecord{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return record, nil
}

// RegisterDocument registers a new document on the ledger.
func (pc *ProvenanceChaincode) RegisterDocument(ctx contractapi.TransactionContextInterface,
	documentID, documentHash, filename, recipientIDsJSON string) error {

	var recipientIDs []string
	if err := json.Unmarshal([]byte(recipientIDsJSON), &recipientIDs); err != nil {
		return fmt.Errorf("invalid recipient IDs: %w", err)
	}

	record := DocumentRecord{
		DocType:      "document",
		DocumentID:   documentID,
		DocumentHash: documentHash,
		Filename:     filename,
		RecipientIDs: recipientIDs,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return ctx.GetStub().PutState("document:"+documentID, data)
}

// RecordDecryption records an immutable decryption event.
func (pc *ProvenanceChaincode) RecordDecryption(ctx contractapi.TransactionContextInterface,
	recordJSON string) error {

	record := &DecryptionRecord{}
	if err := json.Unmarshal([]byte(recordJSON), record); err != nil {
		return fmt.Errorf("malformed record: %w", err)
	}

	// Validate required fields
	if record.EventID == "" || record.DocumentID == "" || record.RecipientID == "" ||
		record.WatermarkID == "" || record.SessionID == "" || record.Signature == "" {
		return fmt.Errorf("malformed record: missing required fields")
	}

	// Check duplicate event ID
	existing, err := ctx.GetStub().GetState("event:" + record.EventID)
	if err != nil {
		return fmt.Errorf("failed to check event: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("duplicate event ID: %s", record.EventID)
	}

	// Check duplicate watermark ID
	existingWM, err := ctx.GetStub().GetState("watermark:" + record.WatermarkID)
	if err != nil {
		return fmt.Errorf("failed to check watermark: %w", err)
	}
	if existingWM != nil {
		return fmt.Errorf("duplicate watermark ID: %s", record.WatermarkID)
	}

	record.DocType = "decryption"
	record.TransactionID = ctx.GetStub().GetTxID()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	// Store by event ID
	if err := ctx.GetStub().PutState("event:"+record.EventID, data); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	// Index by watermark ID
	if err := ctx.GetStub().PutState("watermark:"+record.WatermarkID, []byte(record.EventID)); err != nil {
		return fmt.Errorf("failed to store watermark index: %w", err)
	}

	// Index by document (for history)
	historyKey := fmt.Sprintf("doc-history:%s:%s", record.DocumentID, record.EventID)
	if err := ctx.GetStub().PutState(historyKey, []byte(record.EventID)); err != nil {
		return fmt.Errorf("failed to store doc history: %w", err)
	}

	return nil
}

// GetDecryptionRecord retrieves a decryption record by event ID.
func (pc *ProvenanceChaincode) GetDecryptionRecord(ctx contractapi.TransactionContextInterface,
	eventID string) (*DecryptionRecord, error) {

	data, err := ctx.GetStub().GetState("event:" + eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	record := &DecryptionRecord{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return record, nil
}

// GetByWatermarkID retrieves a decryption record by watermark ID.
func (pc *ProvenanceChaincode) GetByWatermarkID(ctx contractapi.TransactionContextInterface,
	watermarkID string) (*DecryptionRecord, error) {

	eventIDData, err := ctx.GetStub().GetState("watermark:" + watermarkID)
	if err != nil {
		return nil, fmt.Errorf("failed to read watermark index: %w", err)
	}
	if eventIDData == nil {
		return nil, fmt.Errorf("watermark not found: %s", watermarkID)
	}

	return pc.GetDecryptionRecord(ctx, string(eventIDData))
}

// VerifyRecord performs basic record verification on the ledger side.
func (pc *ProvenanceChaincode) VerifyRecord(ctx contractapi.TransactionContextInterface,
	eventID string) (string, error) {

	record, err := pc.GetDecryptionRecord(ctx, eventID)
	if err != nil {
		return "", err
	}

	result := map[string]interface{}{
		"event_found":    true,
		"event_id":       record.EventID,
		"recipient_id":   record.RecipientID,
		"watermark_id":   record.WatermarkID,
		"has_signature":  record.Signature != "",
		"has_public_key": record.RecipientMLDSAPubKey != "",
	}

	data, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetDocumentHistory returns all decryption events for a document.
func (pc *ProvenanceChaincode) GetDocumentHistory(ctx contractapi.TransactionContextInterface,
	documentID string) (string, error) {

	startKey := fmt.Sprintf("doc-history:%s:", documentID)
	endKey := fmt.Sprintf("doc-history:%s:~", documentID)

	iter, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return "", fmt.Errorf("failed to get history: %w", err)
	}
	defer iter.Close()

	var records []*DecryptionRecord
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("iteration error: %w", err)
		}

		eventID := string(kv.Value)
		record, err := pc.GetDecryptionRecord(ctx, eventID)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	data, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&ProvenanceChaincode{})
	if err != nil {
		panic(fmt.Sprintf("Error creating chaincode: %v", err))
	}

	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting chaincode: %v", err))
	}
}
