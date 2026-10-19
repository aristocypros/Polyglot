package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/auth"
)

type mockStore struct {
	keys map[string]*auth.APIKey
}

func newMockStore() *mockStore {
	return &mockStore{keys: make(map[string]*auth.APIKey)}
}

func (m *mockStore) add(token, name, role string, revoked bool) {
	h := auth.HashToken(token)
	var revokedAt *time.Time
	if revoked {
		t := time.Now().Add(-1 * time.Hour)
		revokedAt = &t
	}
	m.keys[h] = &auth.APIKey{
		ID:        uuid.New(),
		Name:      name,
		Role:      role,
		KeyHash:   h,
		RevokedAt: revokedAt,
	}
}

func (m *mockStore) LookupKeyByHash(ctx context.Context, keyHash string) (*auth.APIKey, error) {
	return m.keys[keyHash], nil
}

func TestDualPortServer(t *testing.T) {
	store := newMockStore()
	store.add("client-token", "alice", auth.RoleClient, false)
	store.add("signer-token", "signer-1", auth.RoleSigner, false)
	store.add("revoked-token", "revoked", auth.RoleClient, true)

	// Bind to port 0 for ephemeral ports in tests
	cfg := Config{
		PublicAddr:   "127.0.0.1:0",
		InternalAddr: "127.0.0.1:0",
	}

	srv := New(cfg, nil, store)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() {
		_ = srv.Shutdown(ctx)
	}()

	pubURL := "http://" + srv.PublicAddr()
	intURL := "http://" + srv.InternalAddr()

	httpClient := &http.Client{Timeout: 2 * time.Second}

	// 1. /healthz requires no authentication
	t.Run("Public /healthz returns 200 without auth", func(t *testing.T) {
		resp, err := httpClient.Get(pubURL + "/healthz")
		if err != nil {
			t.Fatalf("health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body["status"] != "ok" {
			t.Errorf("expected status 'ok', got '%s'", body["status"])
		}
	})

	// 2. Client key on /v1/requests returns 200
	t.Run("Client key accepted on /v1/requests", func(t *testing.T) {
		req, _ := http.NewRequest("GET", pubURL+"/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer client-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	// 3. Signer key rejected on /v1/requests (403 Forbidden with RFC 9457 code unauthorized)
	t.Run("Signer key rejected on /v1/requests", func(t *testing.T) {
		req, _ := http.NewRequest("GET", pubURL+"/v1/requests", nil)
		req.Header.Set("Authorization", "Bearer signer-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		var prob ProblemDetails
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		if prob.Code != CodeUnauthorized {
			t.Errorf("expected problem code '%s', got '%s'", CodeUnauthorized, prob.Code)
		}
	})

	// 4. Client key accepted on /v1/wallets
	t.Run("Client key accepted on /v1/wallets", func(t *testing.T) {
		req, _ := http.NewRequest("GET", pubURL+"/v1/wallets", nil)
		req.Header.Set("Authorization", "Bearer client-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	// 5. Signer key rejected on /v1/wallets
	t.Run("Signer key rejected on /v1/wallets", func(t *testing.T) {
		req, _ := http.NewRequest("GET", pubURL+"/v1/wallets", nil)
		req.Header.Set("Authorization", "Bearer signer-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		var prob ProblemDetails
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		if prob.Code != CodeUnauthorized {
			t.Errorf("expected problem code '%s', got '%s'", CodeUnauthorized, prob.Code)
		}
	})

	// 6. Both client and signer accepted on /v1/signer
	t.Run("Both client and signer keys accepted on /v1/signer, as well as unauthenticated", func(t *testing.T) {
		for _, tok := range []string{"client-token", "signer-token"} {
			req, _ := http.NewRequest("GET", pubURL+"/v1/signer", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("token %s expected 200 OK, got %d", tok, resp.StatusCode)
			}
		}

		// Also verify unauthenticated request returns 200 OK
		req, _ := http.NewRequest("GET", pubURL+"/v1/signer", nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("unauthenticated /v1/signer expected 200 OK, got %d", resp.StatusCode)
		}
	})

	// 7. Signer key accepted on /internal/claim
	t.Run("Signer key accepted on internal listener", func(t *testing.T) {
		req, _ := http.NewRequest("POST", intURL+"/internal/claim", nil)
		req.Header.Set("Authorization", "Bearer signer-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 200 OK or 204 No Content, got %d", resp.StatusCode)
		}
	})

	t.Run("Signer key accepted on /internal/results", func(t *testing.T) {
		sub := map[string]any{
			"request_id": "00000000-0000-0000-0000-000000000001",
			"status":     "completed",
		}
		data, _ := json.Marshal(sub)
		req, _ := http.NewRequest("POST", intURL+"/internal/results", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer signer-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	// 8. Client key rejected on /internal/claim
	t.Run("Client key rejected on internal listener", func(t *testing.T) {
		req, _ := http.NewRequest("POST", intURL+"/internal/claim", nil)
		req.Header.Set("Authorization", "Bearer client-token")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		var prob ProblemDetails
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		if prob.Code != CodeUnauthorized {
			t.Errorf("expected problem code '%s', got '%s'", CodeUnauthorized, prob.Code)
		}
	})

	// 9. Revoked and invalid keys return 401 on both public and internal
	t.Run("Revoked and invalid keys return 401 unauthorized", func(t *testing.T) {
		cases := []struct {
			url   string
			token string
		}{
			{pubURL + "/v1/requests", "revoked-token"},
			{pubURL + "/v1/requests", "nonexistent-token"},
			{intURL + "/internal/claim", "revoked-token"},
			{intURL + "/internal/claim", "nonexistent-token"},
		}

		for _, tc := range cases {
			req, _ := http.NewRequest("GET", tc.url, nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("url %s with token %s: expected 401, got %d", tc.url, tc.token, resp.StatusCode)
			}
			var prob ProblemDetails
			_ = json.Unmarshal(body, &prob)
			if prob.Code != CodeUnauthorized {
				t.Errorf("url %s: expected problem code '%s', got '%s'", tc.url, CodeUnauthorized, prob.Code)
			}
		}
	})
}
