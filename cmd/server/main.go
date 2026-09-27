package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cryptoattr/secure-doc-dist/internal/api"
	"github.com/cryptoattr/secure-doc-dist/internal/auth"
	"github.com/cryptoattr/secure-doc-dist/internal/config"
	"github.com/cryptoattr/secure-doc-dist/internal/documents"
	"github.com/cryptoattr/secure-doc-dist/internal/fabric"
	"github.com/cryptoattr/secure-doc-dist/internal/forensic"
	"github.com/cryptoattr/secure-doc-dist/internal/keystore"
	"github.com/cryptoattr/secure-doc-dist/internal/logging"
	"github.com/cryptoattr/secure-doc-dist/internal/provenance"
	miniostorage "github.com/cryptoattr/secure-doc-dist/internal/storage/minio"
)

func main() {
	// Load config
	cfg := config.LoadFromEnv()
	if len(os.Args) > 1 {
		loadedCfg, err := config.LoadFromFile(os.Args[1])
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		cfg = loadedCfg
	}

	// Setup logger
	logger := logging.NewLogger(cfg.Logging.Level, cfg.Logging.Format)
	logger.Info("starting secure document distribution server",
		"version", "1.0.0",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize key store
	var ks keystore.KeyStore
	switch cfg.HSM.Type {
	case "memory":
		logger.Info("using in-memory key store (demo mode)")
		ks = keystore.NewMemoryKeyStore()
	default:
		logger.Info("using in-memory key store (HSM type not configured)")
		ks = keystore.NewMemoryKeyStore()
	}
	defer ks.Close()

	// Initialize storage
	var storage documents.StorageBackend
	if cfg.MinIO.Endpoint != "" && os.Getenv("DISABLE_MINIO") != "true" {
		minioCfg := miniostorage.Config{
			Endpoint:        cfg.MinIO.Endpoint,
			AccessKeyID:     cfg.MinIO.AccessKeyID,
			SecretAccessKey: cfg.MinIO.SecretAccessKey,
			UseSSL:          cfg.MinIO.UseSSL,
			BucketEncrypted: cfg.MinIO.BucketEncrypted,
			BucketWatermark: cfg.MinIO.BucketWatermark,
			BucketForensic:  cfg.MinIO.BucketForensic,
			BucketAudit:     cfg.MinIO.BucketAudit,
		}
		minioStore, err := miniostorage.NewStorage(minioCfg)
		if err != nil {
			logger.Warn("MinIO not available, using memory storage",
				"error", err.Error(),
			)
			storage = NewMemoryStorage()
		} else {
			if err := minioStore.InitBuckets(ctx); err != nil {
				logger.Warn("MinIO bucket init failed, using memory storage",
					"error", err.Error(),
				)
				storage = NewMemoryStorage()
			} else {
				storage = minioStore
				logger.Info("MinIO storage initialized",
					"endpoint", cfg.MinIO.Endpoint,
				)
			}
		}
	} else {
		logger.Info("using in-memory storage (MinIO disabled)")
		storage = NewMemoryStorage()
	}

	// Initialize ledger
	var ledger fabric.Ledger
	if cfg.Fabric.Enabled {
		logger.Info("Fabric enabled but using memory ledger for this build")
		ledger = fabric.NewMemoryLedger()
	} else {
		logger.Info("using in-memory ledger (Fabric disabled)")
		ledger = fabric.NewMemoryLedger()
	}
	defer ledger.Close()

	// Initialize services
	docService := documents.NewService(ks, storage)

	provService, err := provenance.NewService(docService, ks, ledger)
	if err != nil {
		log.Fatalf("Failed to create provenance service: %v", err)
	}

	forensicSvc, err := forensic.NewService(ledger, ks)
	if err != nil {
		log.Fatalf("Failed to create forensic service: %v", err)
	}

	authenticator := auth.NewAuthenticator(cfg.Auth.TokenSecret)

	// Create API server
	apiServer := api.NewServer(
		docService,
		provService,
		forensicSvc,
		ks,
		ledger,
		authenticator,
		logger,
	)

	handler := apiServer.SetupRoutes()

	httpServer := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("shutting down server")
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", "error", err)
		}
		cancel()
	}()

	logger.Info("server starting",
		"address", cfg.Server.Address(),
	)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	logger.Info("server stopped")
}

// MemoryStorage is a simple in-memory document storage for when MinIO is unavailable.
type MemoryStorage struct {
	packages   map[string][]byte
	watermarks map[string][]byte
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		packages:   make(map[string][]byte),
		watermarks: make(map[string][]byte),
	}
}

func (m *MemoryStorage) StorePackage(ctx context.Context, documentID string, data []byte) error {
	m.packages[documentID] = data
	return nil
}

func (m *MemoryStorage) LoadPackage(ctx context.Context, documentID string) ([]byte, error) {
	data, ok := m.packages[documentID]
	if !ok {
		return nil, fmt.Errorf("package not found: %s", documentID)
	}
	return data, nil
}

func (m *MemoryStorage) StoreWatermarked(ctx context.Context, documentID, sessionID string, data []byte) error {
	key := documentID + "/" + sessionID
	m.watermarks[key] = data
	return nil
}

func (m *MemoryStorage) LoadWatermarked(ctx context.Context, documentID, sessionID string) ([]byte, error) {
	key := documentID + "/" + sessionID
	data, ok := m.watermarks[key]
	if !ok {
		return nil, fmt.Errorf("watermarked doc not found: %s", key)
	}
	return data, nil
}
