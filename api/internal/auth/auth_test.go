package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/problem"
)

type mockKeyStore struct {
	keys map[string]*APIKey
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{keys: make(map[string]*APIKey)}
}

func (m *mockKeyStore) addKey(token, name, role string, revoked bool) {
	h := HashToken(token)
	var revokedAt *time.Time
	if revoked {
		t := time.Now().Add(-1 * time.Hour)
		revokedAt = &t
	}
	m.keys[h] = &APIKey{
		ID:        uuid.New(),
		Name:      name,
		Role:      role,
		KeyHash:   h,
		RevokedAt: revokedAt,
	}
}

func (m *mockKeyStore) LookupKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	key, ok := m.keys[keyHash]
	if !ok {
		return nil, nil
	}
	return key, nil
}

func TestAuthMiddleware(t *testing.T) {
	store := newMockKeyStore()
	store.addKey("client-secret-123", "test-client", RoleClient, false)
	store.addKey("signer-secret-456", "test-signer", RoleSigner, false)
	store.addKey("revoked-secret-789", "revoked-client", RoleClient, true)

	// Create test handler wrapped in authentication and specific role checks
	clientOnlyHandler := Authenticate(store)(RequireRole(RoleClient)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := KeyFromContext(r.Context())
		if !ok {
			t.Errorf("expected API key in context")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("hello %s (%s)", key.Name, key.Role)))
	})))

	signerOnlyHandler := Authenticate(store)(RequireRole(RoleSigner)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("signer granted"))
	})))

	anyRoleHandler := Authenticate(store)(RequireAnyRole(RoleClient, RoleSigner)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("any granted"))
	})))

	t.Run("Valid client accessing client route", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer client-secret-123")
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != "hello test-client (client)" {
			t.Errorf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("Signer rejected on client route", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer signer-secret-456")
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d: %s", rec.Code, rec.Body.String())
		}
		var prob problem.ProblemDetails
		if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
			t.Fatalf("failed to parse problem details: %v", err)
		}
		if prob.Code != problem.CodeUnauthorized {
			t.Errorf("expected problem code '%s', got '%s'", problem.CodeUnauthorized, prob.Code)
		}
	})

	t.Run("Client rejected on internal signer route", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/internal/claim", nil)
		req.Header.Set("Authorization", "Bearer client-secret-123")
		rec := httptest.NewRecorder()

		signerOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d: %s", rec.Code, rec.Body.String())
		}
		var prob problem.ProblemDetails
		if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
			t.Fatalf("failed to parse problem details: %v", err)
		}
		if prob.Code != problem.CodeUnauthorized {
			t.Errorf("expected problem code '%s', got '%s'", problem.CodeUnauthorized, prob.Code)
		}
	})

	t.Run("Valid signer accessing internal route", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/internal/claim", nil)
		req.Header.Set("Authorization", "Bearer signer-secret-456")
		rec := httptest.NewRecorder()

		signerOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != "signer granted" {
			t.Errorf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("Both client and signer permitted on anyRole handler", func(t *testing.T) {
		for _, token := range []string{"client-secret-123", "signer-secret-456"} {
			req := httptest.NewRequest("GET", "/v1/signer", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			anyRoleHandler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected 200 OK for token %s, got %d: %s", token, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("Missing Authorization header returns 401 unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		var prob problem.ProblemDetails
		_ = json.Unmarshal(rec.Body.Bytes(), &prob)
		if prob.Code != problem.CodeUnauthorized {
			t.Errorf("expected code unauthorized, got %s", prob.Code)
		}
	})

	t.Run("Malformed header returns 401 unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("Unknown token returns 401 unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer unknown-key-999")
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("Revoked token returns 401 unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer revoked-secret-789")
		rec := httptest.NewRecorder()

		clientOnlyHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})
}
