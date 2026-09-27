// Package config provides application configuration management.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds all application configuration.
type Config struct {
	Server  ServerConfig  `json:"server"`
	MinIO   MinIOConfig   `json:"minio"`
	Fabric  FabricConfig  `json:"fabric"`
	HSM     HSMConfig     `json:"hsm"`
	Logging LogConfig     `json:"logging"`
	Auth    AuthConfig    `json:"auth"`
	Crypto  CryptoConfig  `json:"crypto"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	MaxUploadSizeMB int64         `json:"max_upload_size_mb"`
}

// MinIOConfig holds MinIO connection settings.
type MinIOConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	UseSSL          bool   `json:"use_ssl"`
	BucketEncrypted string `json:"bucket_encrypted"`
	BucketWatermark string `json:"bucket_watermark"`
	BucketForensic  string `json:"bucket_forensic"`
	BucketAudit     string `json:"bucket_audit"`
}

// FabricConfig holds Hyperledger Fabric connection settings.
type FabricConfig struct {
	Enabled          bool   `json:"enabled"`
	MSPID            string `json:"msp_id"`
	CryptoPath       string `json:"crypto_path"`
	CertPath         string `json:"cert_path"`
	KeyPath          string `json:"key_path"`
	TLSCertPath      string `json:"tls_cert_path"`
	PeerEndpoint     string `json:"peer_endpoint"`
	GatewayPeer      string `json:"gateway_peer"`
	ChannelName      string `json:"channel_name"`
	ChaincodeName    string `json:"chaincode_name"`
	OrdererEndpoint  string `json:"orderer_endpoint"`
}

// HSMConfig holds HSM / SoftHSM configuration.
type HSMConfig struct {
	Type       string `json:"type"` // "memory", "softhsm", "pkcs11"
	LibPath    string `json:"lib_path"`
	TokenLabel string `json:"token_label"`
	PIN        string `json:"pin"`
	SlotID     int    `json:"slot_id"`
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level  string `json:"level"` // "debug", "info", "warn", "error"
	Format string `json:"format"` // "json", "text"
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	TokenSecret    string        `json:"token_secret"`
	TokenExpiry    time.Duration `json:"token_expiry"`
}

// CryptoConfig holds cryptographic algorithm configuration.
type CryptoConfig struct {
	KEMAlgorithm       string `json:"kem_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
}

// DefaultConfig returns a configuration with sane defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    120 * time.Second,
			MaxUploadSizeMB: 100,
		},
		MinIO: MinIOConfig{
			Endpoint:        "localhost:9000",
			AccessKeyID:     "minioadmin",
			SecretAccessKey: "minioadmin",
			UseSSL:          false,
			BucketEncrypted: "encrypted-documents",
			BucketWatermark: "watermarked-documents",
			BucketForensic:  "forensic-inputs",
			BucketAudit:     "audit-artifacts",
		},
		Fabric: FabricConfig{
			Enabled:       false,
			MSPID:         "AuditOrgMSP",
			ChannelName:   "audit-channel",
			ChaincodeName: "provenance-chaincode",
		},
		HSM: HSMConfig{
			Type: "memory",
		},
		Logging: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Auth: AuthConfig{
			TokenSecret: "demo-secret-change-in-production",
			TokenExpiry: 24 * time.Hour,
		},
		Crypto: CryptoConfig{
			KEMAlgorithm:        "ML-KEM-768",
			SignatureAlgorithm:  "ML-DSA-65",
			EncryptionAlgorithm: "AES-256-GCM",
			HashAlgorithm:       "SHA-256",
		},
	}
}

// LoadFromFile loads configuration from a JSON file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return cfg, nil
}

// LoadFromEnv loads configuration from environment variables, falling back to defaults.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if v := os.Getenv("SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("MINIO_ENDPOINT"); v != "" {
		cfg.MinIO.Endpoint = v
	}
	if v := os.Getenv("MINIO_ACCESS_KEY"); v != "" {
		cfg.MinIO.AccessKeyID = v
	}
	if v := os.Getenv("MINIO_SECRET_KEY"); v != "" {
		cfg.MinIO.SecretAccessKey = v
	}
	if v := os.Getenv("FABRIC_ENABLED"); v == "true" {
		cfg.Fabric.Enabled = true
	}
	if v := os.Getenv("FABRIC_MSP_ID"); v != "" {
		cfg.Fabric.MSPID = v
	}
	if v := os.Getenv("HSM_TYPE"); v != "" {
		cfg.HSM.Type = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("AUTH_TOKEN_SECRET"); v != "" {
		cfg.Auth.TokenSecret = v
	}

	return cfg
}

// Address returns the server listen address.
func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}
