// Package minio provides MinIO-based S3-compatible storage.
package minio

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Storage implements the document storage backend using MinIO.
type Storage struct {
	client          *minio.Client
	bucketEncrypted string
	bucketWatermark string
	bucketForensic  string
	bucketAudit     string
}

// Config holds MinIO connection configuration.
type Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
	BucketEncrypted string
	BucketWatermark string
	BucketForensic  string
	BucketAudit     string
}

// NewStorage creates a new MinIO storage backend.
func NewStorage(cfg Config) (*Storage, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("creating MinIO client: %w", err)
	}

	return &Storage{
		client:          client,
		bucketEncrypted: cfg.BucketEncrypted,
		bucketWatermark: cfg.BucketWatermark,
		bucketForensic:  cfg.BucketForensic,
		bucketAudit:     cfg.BucketAudit,
	}, nil
}

// InitBuckets ensures all required buckets exist.
func (s *Storage) InitBuckets(ctx context.Context) error {
	buckets := []string{
		s.bucketEncrypted,
		s.bucketWatermark,
		s.bucketForensic,
		s.bucketAudit,
	}

	for _, bucket := range buckets {
		exists, err := s.client.BucketExists(ctx, bucket)
		if err != nil {
			return fmt.Errorf("checking bucket %s: %w", bucket, err)
		}
		if !exists {
			if err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
				return fmt.Errorf("creating bucket %s: %w", bucket, err)
			}
		}
	}
	return nil
}

// StorePackage stores an encrypted document package.
func (s *Storage) StorePackage(ctx context.Context, documentID string, data []byte) error {
	objectName := fmt.Sprintf("%s/package.bin", documentID)
	reader := bytes.NewReader(data)
	_, err := s.client.PutObject(ctx, s.bucketEncrypted, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("storing package: %w", err)
	}
	return nil
}

// LoadPackage loads an encrypted document package.
func (s *Storage) LoadPackage(ctx context.Context, documentID string) ([]byte, error) {
	objectName := fmt.Sprintf("%s/package.bin", documentID)
	obj, err := s.client.GetObject(ctx, s.bucketEncrypted, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading package: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("reading package: %w", err)
	}
	return data, nil
}

// StoreWatermarked stores a watermarked document.
func (s *Storage) StoreWatermarked(ctx context.Context, documentID, sessionID string, data []byte) error {
	objectName := fmt.Sprintf("%s/%s.pdf", documentID, sessionID)
	reader := bytes.NewReader(data)
	_, err := s.client.PutObject(ctx, s.bucketWatermark, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/pdf",
	})
	if err != nil {
		return fmt.Errorf("storing watermarked document: %w", err)
	}
	return nil
}

// LoadWatermarked loads a watermarked document.
func (s *Storage) LoadWatermarked(ctx context.Context, documentID, sessionID string) ([]byte, error) {
	objectName := fmt.Sprintf("%s/%s.pdf", documentID, sessionID)
	obj, err := s.client.GetObject(ctx, s.bucketWatermark, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading watermarked document: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("reading watermarked document: %w", err)
	}
	return data, nil
}

// StoreForensic stores a forensic input document.
func (s *Storage) StoreForensic(ctx context.Context, caseID string, data []byte) error {
	objectName := fmt.Sprintf("%s/input.bin", caseID)
	reader := bytes.NewReader(data)
	_, err := s.client.PutObject(ctx, s.bucketForensic, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("storing forensic input: %w", err)
	}
	return nil
}

// StoreAuditArtifact stores an audit artifact.
func (s *Storage) StoreAuditArtifact(ctx context.Context, name string, data []byte) error {
	reader := bytes.NewReader(data)
	_, err := s.client.PutObject(ctx, s.bucketAudit, name, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	if err != nil {
		return fmt.Errorf("storing audit artifact: %w", err)
	}
	return nil
}
