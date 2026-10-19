package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/problem"
)

// Recognized API roles.
const (
	RoleClient = "client"
	RoleSigner = "signer"
)

// APIKey represents an authenticated API key row from app.api_keys.
type APIKey struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	KeyHash   string     `json:"key_hash"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// KeyStore defines the interface for looking up active API keys.
type KeyStore interface {
	LookupKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
}

// DBKeyStore is a PostgreSQL-backed KeyStore querying app.api_keys.
type DBKeyStore struct {
	db *sql.DB
}

// NewDBKeyStore creates a new DBKeyStore instance.
func NewDBKeyStore(db *sql.DB) *DBKeyStore {
	return &DBKeyStore{db: db}
}

// LookupKeyByHash queries app.api_keys for an unrevoked key matching the given SHA-256 hash.
func (s *DBKeyStore) LookupKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	const query = `
		SELECT id, name, role, key_hash, revoked_at
		FROM app.api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
	`
	var k APIKey
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, keyHash).Scan(
		&k.ID,
		&k.Name,
		&k.Role,
		&k.KeyHash,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query api key: %w", err)
	}
	if revokedAt.Valid {
		k.RevokedAt = &revokedAt.Time
	}
	return &k, nil
}

// HashToken computes the lowercase hex-encoded SHA-256 hash of a bearer token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type contextKey struct{}

var apiKeyContextKey = contextKey{}

// WithAPIKey embeds the authenticated APIKey into the context.
func WithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, apiKeyContextKey, key)
}

// KeyFromContext extracts the authenticated APIKey from the context, if present.
func KeyFromContext(ctx context.Context) (*APIKey, bool) {
	key, ok := ctx.Value(apiKeyContextKey).(*APIKey)
	return key, ok && key != nil
}

// Authenticate returns a middleware that validates Bearer token authentication.
func Authenticate(store KeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("missing Authorization header"))
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("invalid Authorization header format, expected 'Bearer <token>'"))
				return
			}

			token := strings.TrimSpace(parts[1])
			keyHash := HashToken(token)

			key, err := store.LookupKeyByHash(r.Context(), keyHash)
			if err != nil {
				_ = problem.WriteDetails(w, problem.New(
					http.StatusInternalServerError,
					problem.CodeUnauthorized,
					"Authentication Error",
					"failed to verify credentials",
				))
				return
			}

			if key == nil || key.RevokedAt != nil {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("invalid, unknown, or revoked bearer token"))
				return
			}

			ctx := WithAPIKey(r.Context(), key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns a middleware requiring the authenticated caller to have the exact specified role.
func RequireRole(requiredRole string) func(http.Handler) http.Handler {
	return RequireAnyRole(requiredRole)
}

// RequireAnyRole returns a middleware requiring the caller to have one of the allowed roles.
func RequireAnyRole(allowedRoles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := KeyFromContext(r.Context())
			if !ok {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("authentication required"))
				return
			}

			if _, match := allowed[key.Role]; !match {
				_ = problem.WriteDetails(w, problem.ErrForbidden(fmt.Sprintf(
					"role '%s' is not authorized for this route (required: %s)",
					key.Role,
					strings.Join(allowedRoles, ", "),
				)))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthenticateOptional returns a middleware that checks credentials if an Authorization header
// is present, enforcing one of allowedRoles. If no Authorization header is present, the request
// is permitted to proceed without authentication.
func AuthenticateOptional(store KeyStore, allowedRoles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("invalid Authorization header format, expected 'Bearer <token>'"))
				return
			}

			token := strings.TrimSpace(parts[1])
			keyHash := HashToken(token)

			key, err := store.LookupKeyByHash(r.Context(), keyHash)
			if err != nil {
				_ = problem.WriteDetails(w, problem.New(
					http.StatusInternalServerError,
					problem.CodeUnauthorized,
					"Authentication Error",
					"failed to verify credentials",
				))
				return
			}

			if key == nil || key.RevokedAt != nil {
				_ = problem.WriteDetails(w, problem.ErrUnauthorized("invalid, unknown, or revoked bearer token"))
				return
			}

			if len(allowedRoles) > 0 {
				if _, match := allowed[key.Role]; !match {
					_ = problem.WriteDetails(w, problem.ErrForbidden(fmt.Sprintf(
						"role '%s' is not authorized for this route (required: %s)",
						key.Role,
						strings.Join(allowedRoles, ", "),
					)))
					return
				}
			}

			ctx := WithAPIKey(r.Context(), key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

