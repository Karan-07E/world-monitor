// Package logging provides structured logging for the application.
package logging

import (
	"context"
	"log/slog"
	"os"
)

type contextKey string

const (
	requestIDKey  contextKey = "request_id"
	eventIDKey    contextKey = "event_id"
	recipientKey  contextKey = "recipient_id"
	documentKey   contextKey = "document_id"
)

// Logger wraps slog.Logger with application-specific helpers.
type Logger struct {
	*slog.Logger
}

// NewLogger creates a new structured logger.
func NewLogger(level string, format string) *Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return &Logger{Logger: slog.New(handler)}
}

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// WithEventID adds an event ID to the context.
func WithEventID(ctx context.Context, eventID string) context.Context {
	return context.WithValue(ctx, eventIDKey, eventID)
}

// WithRecipientID adds a recipient ID to the context.
func WithRecipientID(ctx context.Context, recipientID string) context.Context {
	return context.WithValue(ctx, recipientKey, recipientID)
}

// WithDocumentID adds a document ID to the context.
func WithDocumentID(ctx context.Context, documentID string) context.Context {
	return context.WithValue(ctx, documentKey, documentID)
}

// FromContext creates a logger with context-specific fields.
func (l *Logger) FromContext(ctx context.Context) *slog.Logger {
	logger := l.Logger
	if v, ok := ctx.Value(requestIDKey).(string); ok && v != "" {
		logger = logger.With("request_id", v)
	}
	if v, ok := ctx.Value(eventIDKey).(string); ok && v != "" {
		logger = logger.With("event_id", v)
	}
	if v, ok := ctx.Value(recipientKey).(string); ok && v != "" {
		logger = logger.With("recipient_id", v)
	}
	if v, ok := ctx.Value(documentKey).(string); ok && v != "" {
		logger = logger.With("document_id", v)
	}
	return logger
}
