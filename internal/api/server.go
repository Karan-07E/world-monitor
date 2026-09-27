// Package api provides the REST API handlers and router setup.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cryptoattr/secure-doc-dist/internal/auth"
	"github.com/cryptoattr/secure-doc-dist/internal/documents"
	"github.com/cryptoattr/secure-doc-dist/internal/fabric"
	"github.com/cryptoattr/secure-doc-dist/internal/forensic"
	"github.com/cryptoattr/secure-doc-dist/internal/keystore"
	"github.com/cryptoattr/secure-doc-dist/internal/logging"
	"github.com/cryptoattr/secure-doc-dist/internal/metrics"
	"github.com/cryptoattr/secure-doc-dist/internal/provenance"
)

const (
	maxUploadSize = 100 << 20 // 100 MB
	version       = "1.0.0"
)

// Server holds all dependencies for the API.
type Server struct {
	docService   *documents.Service
	provService  *provenance.Service
	forensicSvc  *forensic.Service
	keyStore     keystore.KeyStore
	ledger       fabric.Ledger
	auth         *auth.Authenticator
	logger       *logging.Logger
	recipients   map[string]*documents.Recipient
}

// NewServer creates a new API server.
func NewServer(
	docSvc *documents.Service,
	provSvc *provenance.Service,
	forensicSvc *forensic.Service,
	ks keystore.KeyStore,
	ledger fabric.Ledger,
	authenticator *auth.Authenticator,
	logger *logging.Logger,
) *Server {
	return &Server{
		docService:  docSvc,
		provService: provSvc,
		forensicSvc: forensicSvc,
		keyStore:    ks,
		ledger:      ledger,
		auth:        authenticator,
		logger:      logger,
		recipients:  make(map[string]*documents.Recipient),
	}
}

// SetupRoutes configures all API routes using the standard library mux.
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Health and info
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/ready", s.handleReady)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("GET /api/v1/metrics", s.handleMetrics)

	// Recipients
	mux.HandleFunc("POST /api/v1/recipients", s.handleCreateRecipient)
	mux.HandleFunc("GET /api/v1/recipients/{id}", s.handleGetRecipient)

	// Documents
	mux.HandleFunc("POST /api/v1/documents", s.handleUploadDocument)
	mux.HandleFunc("GET /api/v1/documents/{id}", s.handleGetDocument)
	mux.HandleFunc("POST /api/v1/documents/{id}/decrypt", s.handleDecryptDocument)
	mux.HandleFunc("GET /api/v1/documents/{id}/audit", s.handleGetDocumentAudit)

	// Forensics
	mux.HandleFunc("POST /api/v1/forensics/extract", s.handleForensicExtract)
	mux.HandleFunc("POST /api/v1/forensics/verify", s.handleForensicVerify)
	mux.HandleFunc("GET /api/v1/forensics/{watermarkID}", s.handleGetForensicByWatermark)

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID, _ := documents.GenerateRandomID(8)

		ctx := logging.WithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)

		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Content-Type", "application/json")

		s.logger.FromContext(ctx).Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)

		next.ServeHTTP(w, r)

		s.logger.FromContext(ctx).Info("response",
			"method", r.Method,
			"path", r.URL.Path,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// --- Health endpoints ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": version,
		"crypto": map[string]string{
			"encryption":        "AES-256-GCM",
			"key_encapsulation": "ML-KEM-768",
			"signature":         "ML-DSA-65",
			"hash":              "SHA-256",
			"key_derivation":    "HKDF-SHA-256",
		},
		"watermark": "DWT-DCT-QIM-RS",
		"ledger":    "Hyperledger Fabric",
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, metrics.Global.Snapshot())
}

// --- Recipient endpoints ---

func (s *Server) handleCreateRecipient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		RecipientID string `json:"recipient_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RecipientID == "" {
		writeError(w, http.StatusBadRequest, "recipient_id is required")
		return
	}

	// Sanitize recipient ID
	if !isValidID(req.RecipientID) {
		writeError(w, http.StatusBadRequest, "invalid recipient_id format")
		return
	}

	kemKeyID := req.RecipientID + "-kem-v1"
	dsaKeyID := req.RecipientID + "-sign-v1"

	// Generate ML-KEM-768 key pair
	if err := s.keyStore.GenerateMLKEMKeyPair(ctx, kemKeyID); err != nil {
		s.logger.FromContext(ctx).Error("generating ML-KEM keypair", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate KEM keypair")
		return
	}

	// Generate ML-DSA-65 key pair
	if err := s.keyStore.GenerateMLDSAKeyPair(ctx, dsaKeyID); err != nil {
		s.logger.FromContext(ctx).Error("generating ML-DSA keypair", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate DSA keypair")
		return
	}

	// Get public keys for registration
	kemPubKey, err := s.keyStore.GetMLKEMPublicKey(ctx, kemKeyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get KEM public key")
		return
	}

	dsaPubKey, err := s.keyStore.GetMLDSAPublicKey(ctx, dsaKeyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get DSA public key")
		return
	}

	// Register on ledger
	if err := s.ledger.RegisterRecipient(ctx, req.RecipientID, req.DisplayName, dsaPubKey, kemPubKey); err != nil {
		s.logger.FromContext(ctx).Error("registering recipient on ledger", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to register on ledger")
		return
	}

	// Register for auth
	apiKey, err := s.auth.RegisterUser(req.RecipientID, req.DisplayName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to register auth")
		return
	}

	recipient := &documents.Recipient{
		RecipientID:  req.RecipientID,
		DisplayName:  req.DisplayName,
		KEMKeyID:     kemKeyID,
		DSAKeyID:     dsaKeyID,
		CreatedAt:    time.Now().UTC(),
		Active:       true,
	}
	s.recipients[req.RecipientID] = recipient

	s.logger.FromContext(ctx).Info("recipient registered",
		"recipient_id", req.RecipientID,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"recipient_id": req.RecipientID,
		"display_name": req.DisplayName,
		"kem_key_id":   kemKeyID,
		"dsa_key_id":   dsaKeyID,
		"api_key":      apiKey,
		"algorithms": map[string]string{
			"kem":       "ML-KEM-768",
			"signature": "ML-DSA-65",
		},
	})
}

func (s *Server) handleGetRecipient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "recipient ID required")
		return
	}

	recipient, ok := s.recipients[id]
	if !ok {
		writeError(w, http.StatusNotFound, "recipient not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"recipient_id": recipient.RecipientID,
		"display_name": recipient.DisplayName,
		"kem_key_id":   recipient.KEMKeyID,
		"dsa_key_id":   recipient.DSAKeyID,
		"active":       recipient.Active,
		"created_at":   recipient.CreatedAt,
	})
}

// --- Document endpoints ---

func (s *Server) handleUploadDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "file too large or invalid form")
		return
	}

	file, header, err := r.FormFile("document")
	if err != nil {
		writeError(w, http.StatusBadRequest, "document file required")
		return
	}
	defer file.Close()

	// Validate filename
	filename := sanitizeFilename(header.Filename)
	if filename == "" {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	// Read file
	fileData, err := io.ReadAll(io.LimitReader(file, maxUploadSize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read file")
		return
	}

	// Get recipients
	recipientsStr := r.FormValue("recipients")
	if recipientsStr == "" {
		writeError(w, http.StatusBadRequest, "recipients field required")
		return
	}
	recipientIDs := strings.Split(recipientsStr, ",")
	for i := range recipientIDs {
		recipientIDs[i] = strings.TrimSpace(recipientIDs[i])
	}

	// Encrypt
	pkg, err := s.docService.EncryptDocument(ctx, filename, fileData, recipientIDs)
	if err != nil {
		s.logger.FromContext(ctx).Error("encrypting document", "error", err)
		writeError(w, http.StatusInternalServerError, "encryption failed: "+err.Error())
		return
	}

	// Register on ledger
	if err := s.ledger.RegisterDocument(ctx, pkg.DocumentID, pkg.DocumentSHA256, filename, recipientIDs); err != nil {
		s.logger.FromContext(ctx).Error("registering document on ledger", "error", err)
	}

	s.logger.FromContext(ctx).Info("document uploaded and encrypted",
		"document_id", pkg.DocumentID,
		"filename", filename,
		"recipients", recipientIDs,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"document_id": pkg.DocumentID,
		"package_id":  pkg.PackageID,
		"filename":    filename,
		"sha256":      pkg.DocumentSHA256,
		"recipients":  recipientIDs,
		"algorithm": map[string]string{
			"encryption": "AES-256-GCM",
			"kem":        "ML-KEM-768",
			"signature":  "ML-DSA-65",
		},
	})
}

func (s *Server) handleGetDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "document ID required")
		return
	}

	// Get document metadata from ledger
	history, err := s.ledger.GetDocumentHistory(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"document_id":      id,
		"decryption_count": len(history),
	})
}

func (s *Server) handleDecryptDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	documentID := r.PathValue("id")
	if documentID == "" {
		writeError(w, http.StatusBadRequest, "document ID required")
		return
	}

	// Authenticate recipient
	recipientID := s.authenticateRequest(r)
	if recipientID == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	ctx = logging.WithDocumentID(ctx, documentID)
	ctx = logging.WithRecipientID(ctx, recipientID)

	s.logger.FromContext(ctx).Info("decryption request",
		"document_id", documentID,
		"recipient_id", recipientID,
	)

	// Perform complete decryption with provenance
	start := time.Now()
	output, err := s.provService.DecryptWithProvenance(ctx, documentID, recipientID)
	if err != nil {
		s.logger.FromContext(ctx).Error("decryption failed", "error", err)
		writeError(w, http.StatusInternalServerError, "decryption failed: "+err.Error())
		return
	}
	duration := time.Since(start)

	metrics.Global.DecryptionsTotal.Add(1)
	metrics.Global.WatermarkEmbeddingsTotal.Add(1)
	metrics.Global.FabricTransactionsTotal.Add(1)
	metrics.Global.RecordCryptoOp("total_decryption", duration)

	s.logger.FromContext(ctx).Info("decryption successful",
		"event_id", output.EventID,
		"watermark_id", output.WatermarkID,
		"transaction_id", output.TransactionID,
		"duration_ms", duration.Milliseconds(),
	)

	// Return watermarked PDF
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-watermarked.pdf\"", recipientID))
	w.Header().Set("X-Event-ID", output.EventID)
	w.Header().Set("X-Watermark-ID", output.WatermarkID)
	w.Header().Set("X-Session-ID", output.SessionID)
	w.Header().Set("X-Transaction-ID", output.TransactionID)
	w.WriteHeader(http.StatusOK)
	w.Write(output.WatermarkedDoc)
}

func (s *Server) handleGetDocumentAudit(w http.ResponseWriter, r *http.Request) {
	documentID := r.PathValue("id")
	if documentID == "" {
		writeError(w, http.StatusBadRequest, "document ID required")
		return
	}

	history, err := s.ledger.GetDocumentHistory(r.Context(), documentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get audit history")
		return
	}

	events := make([]map[string]interface{}, 0, len(history))
	for _, rec := range history {
		events = append(events, map[string]interface{}{
			"event_id":       rec.EventID,
			"recipient_id":   rec.RecipientID,
			"watermark_id":   rec.WatermarkID,
			"session_id":     rec.SessionID,
			"timestamp":      rec.Timestamp,
			"transaction_id": rec.TransactionID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"document_id": documentID,
		"events":      events,
		"count":       len(events),
	})
}

// --- Forensic endpoints ---

func (s *Server) handleForensicExtract(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "file too large or invalid form")
		return
	}

	file, _, err := r.FormFile("document")
	if err != nil {
		writeError(w, http.StatusBadRequest, "document file required")
		return
	}
	defer file.Close()

	docData, err := io.ReadAll(io.LimitReader(file, maxUploadSize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read file")
		return
	}

	start := time.Now()
	report, err := s.forensicSvc.ExtractAndAttribute(ctx, docData)
	if err != nil {
		s.logger.FromContext(ctx).Error("forensic extraction failed", "error", err)
		writeError(w, http.StatusInternalServerError, "forensic extraction failed: "+err.Error())
		return
	}
	duration := time.Since(start)

	metrics.Global.WatermarkExtractionsTotal.Add(1)
	if report.Status == "VERIFIED" {
		metrics.Global.AttributionSuccessTotal.Add(1)
	} else {
		metrics.Global.AttributionFailureTotal.Add(1)
	}

	s.logger.FromContext(ctx).Info("forensic extraction",
		"case_id", report.CaseID,
		"status", report.Status,
		"watermark_id", report.WatermarkID,
		"recipient_id", report.Recipient.RecipientID,
		"duration_ms", duration.Milliseconds(),
	)

	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleForensicVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WatermarkID string `json:"watermark_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.WatermarkID == "" {
		writeError(w, http.StatusBadRequest, "watermark_id required")
		return
	}

	result, err := s.forensicSvc.VerifyByWatermarkID(r.Context(), req.WatermarkID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetForensicByWatermark(w http.ResponseWriter, r *http.Request) {
	watermarkID := r.PathValue("watermarkID")
	if watermarkID == "" {
		writeError(w, http.StatusBadRequest, "watermark ID required")
		return
	}

	record, err := s.ledger.GetByWatermarkID(r.Context(), watermarkID)
	if err != nil {
		writeError(w, http.StatusNotFound, "watermark not found in ledger")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"found":          true,
		"watermark_id":   record.WatermarkID,
		"document_id":    record.DocumentID,
		"session_id":     record.SessionID,
		"recipient_id":   record.RecipientID,
		"timestamp":      record.Timestamp,
		"transaction_id": record.TransactionID,
		"event_id":       record.EventID,
	})
}

// --- Helpers ---

func (s *Server) authenticateRequest(r *http.Request) string {
	// Check X-API-Key header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Check query parameter
		apiKey = r.URL.Query().Get("api_key")
	}
	if apiKey == "" {
		// Check JSON body for recipient_id (demo mode)
		var body struct {
			RecipientID string `json:"recipient_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.RecipientID != "" {
			// In demo mode, accept recipient_id directly
			return body.RecipientID
		}
		return ""
	}

	recipientID, err := s.auth.Authenticate(apiKey)
	if err != nil {
		return ""
	}
	return recipientID
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func isValidID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func sanitizeFilename(name string) string {
	// Remove path components
	name = strings.ReplaceAll(name, "/", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "..", "")

	if len(name) > 255 {
		name = name[:255]
	}
	return name
}
