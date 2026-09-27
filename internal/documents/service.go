// Package documents provides the document encryption/decryption service.
package documents

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/cryptoattr/secure-doc-dist/internal/crypto/aesgcm"
	cryptohkdf "github.com/cryptoattr/secure-doc-dist/internal/crypto/hkdf"
	"github.com/cryptoattr/secure-doc-dist/internal/crypto/mlkem"
	"github.com/cryptoattr/secure-doc-dist/internal/keystore"
)

// Service handles document encryption, storage, and decryption.
type Service struct {
	keyStore keystore.KeyStore
	storage  StorageBackend
}

// StorageBackend defines the interface for document storage.
type StorageBackend interface {
	StorePackage(ctx context.Context, documentID string, data []byte) error
	LoadPackage(ctx context.Context, documentID string) ([]byte, error)
	StoreWatermarked(ctx context.Context, documentID, sessionID string, data []byte) error
	LoadWatermarked(ctx context.Context, documentID, sessionID string) ([]byte, error)
}

// NewService creates a new document service.
func NewService(ks keystore.KeyStore, storage StorageBackend) *Service {
	return &Service{
		keyStore: ks,
		storage:  storage,
	}
}

// EncryptDocument encrypts a document for the specified recipients using envelope encryption.
func (s *Service) EncryptDocument(ctx context.Context, filename string, plaintext []byte, recipientIDs []string) (*EncryptedDocumentPackage, error) {
	// 1. Validate
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("document is empty")
	}
	if len(recipientIDs) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// 2. Compute document hash
	docHash := ComputeSHA256(plaintext)

	// 3. Generate random AES-256 document key
	docKey, err := aesgcm.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating document key: %w", err)
	}
	defer func() {
		for i := range docKey {
			docKey[i] = 0
		}
	}()

	// 4. Encrypt document with AES-256-GCM
	nonce, ciphertext, err := aesgcm.Encrypt(docKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypting document: %w", err)
	}

	// 5. Generate IDs
	documentID, err := GenerateRandomID(16)
	if err != nil {
		return nil, err
	}
	packageID, err := GenerateRandomID(16)
	if err != nil {
		return nil, err
	}

	// 6. For each recipient, encapsulate the document key
	envelopes := make([]RecipientEnvelope, 0, len(recipientIDs))
	for _, recipientID := range recipientIDs {
		kemKeyID := recipientID + "-kem-v1"

		// Get recipient's ML-KEM public key
		pubKeyBytes, err := s.keyStore.GetMLKEMPublicKey(ctx, kemKeyID)
		if err != nil {
			return nil, fmt.Errorf("getting ML-KEM public key for %s: %w", recipientID, err)
		}

		// Parse public key
		pk, err := mlkem.UnmarshalPublicKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing ML-KEM public key for %s: %w", recipientID, err)
		}

		// Encapsulate
		kemCT, sharedSecret, err := mlkem.Encapsulate(pk)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM encapsulation for %s: %w", recipientID, err)
		}
		defer func() {
			for i := range sharedSecret {
				sharedSecret[i] = 0
			}
		}()

		// Generate salt for HKDF
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("generating HKDF salt: %w", err)
		}

		// Derive KEK using HKDF-SHA-256
		kek, err := cryptohkdf.DeriveDocumentKeyWrapKey(sharedSecret, salt)
		if err != nil {
			return nil, fmt.Errorf("deriving KEK for %s: %w", recipientID, err)
		}
		defer func() {
			for i := range kek {
				kek[i] = 0
			}
		}()

		// Wrap AES document key with KEK
		wrapNonce, wrappedKey, err := aesgcm.WrapKey(kek, docKey)
		if err != nil {
			return nil, fmt.Errorf("wrapping document key for %s: %w", recipientID, err)
		}

		envelopes = append(envelopes, RecipientEnvelope{
			RecipientID:   recipientID,
			KEMAlgorithm:  "ML-KEM-768",
			KEMCiphertext: kemCT,
			WrappedAESKey: wrappedKey,
			WrapNonce:     wrapNonce,
			WrapSalt:      salt,
			KEMKeyID:      kemKeyID,
		})
	}

	pkg := &EncryptedDocumentPackage{
		PackageID:          packageID,
		DocumentID:         documentID,
		OriginalFilename:   filename,
		DocumentSHA256:     docHash,
		AESGCMNonce:        nonce,
		EncryptedDocument:  ciphertext,
		RecipientEnvelopes: envelopes,
		AlgorithmMetadata:  DefaultAlgorithms(),
		Version:            "1",
		CreatedAt:          time.Now().UTC(),
	}

	// 7. Serialize and store
	pkgData, err := json.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("serializing package: %w", err)
	}

	if err := s.storage.StorePackage(ctx, documentID, pkgData); err != nil {
		return nil, fmt.Errorf("storing package: %w", err)
	}

	// Clear encrypted document from return value (it's in storage)
	returnPkg := *pkg
	returnPkg.EncryptedDocument = nil

	return &returnPkg, nil
}

// DecryptForRecipient decrypts a document for a specific recipient.
// Returns the plaintext. The caller is responsible for watermarking before release.
func (s *Service) DecryptForRecipient(ctx context.Context, documentID, recipientID string) (plaintext []byte, pkg *EncryptedDocumentPackage, err error) {
	// 1. Load encrypted package
	pkgData, err := s.storage.LoadPackage(ctx, documentID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading package: %w", err)
	}

	pkg = &EncryptedDocumentPackage{}
	if err := json.Unmarshal(pkgData, pkg); err != nil {
		return nil, nil, fmt.Errorf("deserializing package: %w", err)
	}

	// 2. Find recipient's envelope
	var envelope *RecipientEnvelope
	for i := range pkg.RecipientEnvelopes {
		if pkg.RecipientEnvelopes[i].RecipientID == recipientID {
			envelope = &pkg.RecipientEnvelopes[i]
			break
		}
	}
	if envelope == nil {
		return nil, nil, fmt.Errorf("recipient %s not authorized for document %s", recipientID, documentID)
	}

	// 3. Decapsulate using HSM/KeyStore
	kemKeyID := envelope.KEMKeyID
	sharedSecret, err := s.keyStore.DecapsulateMLKEM(ctx, kemKeyID, envelope.KEMCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM decapsulation: %w", err)
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// 4. Derive KEK
	kek, err := cryptohkdf.DeriveDocumentKeyWrapKey(sharedSecret, envelope.WrapSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving KEK: %w", err)
	}
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	// 5. Unwrap AES document key
	docKey, err := aesgcm.UnwrapKey(kek, envelope.WrapNonce, envelope.WrappedAESKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrapping document key: %w", err)
	}
	defer func() {
		for i := range docKey {
			docKey[i] = 0
		}
	}()

	// 6. Decrypt document
	plaintext, err = aesgcm.Decrypt(docKey, pkg.AESGCMNonce, pkg.EncryptedDocument)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting document: %w", err)
	}

	// 7. Verify document hash
	computedHash := ComputeSHA256(plaintext)
	if computedHash != pkg.DocumentSHA256 {
		// Zero plaintext
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, nil, fmt.Errorf("document hash mismatch: expected %s, got %s", pkg.DocumentSHA256, computedHash)
	}

	return plaintext, pkg, nil
}
