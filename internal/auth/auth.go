// Package auth provides local authentication for the demo environment.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type contextKey string

const authContextKey contextKey = "auth_recipient_id"

// Authenticator provides local authentication.
type Authenticator struct {
	mu       sync.RWMutex
	users    map[string]*UserCredential
	secret   string
}

// UserCredential represents a local user credential.
type UserCredential struct {
	RecipientID  string `json:"recipient_id"`
	APIKey       string `json:"api_key"`
	DisplayName  string `json:"display_name"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewAuthenticator creates a new local authenticator.
func NewAuthenticator(secret string) *Authenticator {
	return &Authenticator{
		users:  make(map[string]*UserCredential),
		secret: secret,
	}
}

// RegisterUser registers a user and returns an API key.
func (a *Authenticator) RegisterUser(recipientID, displayName string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Generate API key
	apiKey := generateAPIKey(recipientID, a.secret)

	a.users[recipientID] = &UserCredential{
		RecipientID: recipientID,
		APIKey:      apiKey,
		DisplayName: displayName,
		CreatedAt:   time.Now().UTC(),
	}

	return apiKey, nil
}

// Authenticate validates an API key and returns the recipient ID.
func (a *Authenticator) Authenticate(apiKey string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, user := range a.users {
		if user.APIKey == apiKey {
			return user.RecipientID, nil
		}
	}
	return "", fmt.Errorf("invalid API key")
}

// GetUser retrieves a user by recipient ID.
func (a *Authenticator) GetUser(recipientID string) (*UserCredential, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, ok := a.users[recipientID]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", recipientID)
	}
	return user, nil
}

// SetRecipientInContext stores the authenticated recipient ID in context.
func SetRecipientInContext(ctx context.Context, recipientID string) context.Context {
	return context.WithValue(ctx, authContextKey, recipientID)
}

// GetRecipientFromContext retrieves the authenticated recipient ID from context.
func GetRecipientFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(authContextKey).(string)
	return v, ok
}

func generateAPIKey(recipientID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(recipientID))
	mac.Write([]byte(time.Now().UTC().String()))
	return hex.EncodeToString(mac.Sum(nil))
}
