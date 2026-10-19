package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/auth"
	"polyglot/api/internal/db"
	"polyglot/api/internal/problem"
)

func makeTestRequestBody(id string, exp time.Time) RequestBody {
	if id == "" {
		id = uuid.New().String()
	}
	return RequestBody{
		V:               1,
		Type:            "create_wallet",
		RequestID:       id,
		Nonce:           "0123456789abcdef0123456789abcdef",
		Audience:        "signer-local-1",
		ExpiresAt:       exp.UTC().Format(time.RFC3339),
		DecisionID:      "dec-test-123",
		WalletID:        "w_test_" + id[:8],
		Scheme:          "bip32",
		Curve:           "secp256k1",
		Path:            []uint32{2147483692, 2147483648, 2147483648, 0, 0},
		PayloadEncoding: "digest",
		Payload:         "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	}
}

func encodeTestEnvelope(req RequestBody, label *string) SubmitRequestEnvelope {
	raw, _ := json.Marshal(req)
	return SubmitRequestEnvelope{
		Body: base64.RawURLEncoding.EncodeToString(raw),
		Authorization: map[string]any{
			"kid": "pe-dev-1",
			"alg": "ed25519",
			"sig": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		Label: label,
	}
}

func setupTestPostgres(t *testing.T) (adminURL, apiURL string, cleanup func()) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found, skipping Postgres integration test")
		return "", "", func() {}
	}

	containerName := fmt.Sprintf("polyglot-pg-handlers-test-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "-d", "--name", containerName, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=postgres", "postgres:16")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("failed to start postgres container: %v (output: %s)", err, string(out))
		return "", "", func() {}
	}
	containerID := strings.TrimSpace(string(out))

	cleanup = func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	}

	ready := false
	for i := 0; i < 30; i++ {
		checkCmd := exec.Command("docker", "exec", containerID, "pg_isready", "-U", "postgres")
		if err := checkCmd.Run(); err == nil {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !ready {
		cleanup()
		t.Fatalf("postgres container failed to become ready in time")
	}

	portCmd := exec.Command("docker", "port", containerID, "5432")
	portOut, err := portCmd.CombinedOutput()
	if err != nil {
		cleanup()
		t.Fatalf("failed to get docker port: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(portOut)), "\n")
	if len(lines) == 0 {
		cleanup()
		t.Fatalf("no port mapping found: %s", string(portOut))
	}
	hostPortPart := strings.TrimSpace(lines[0])
	parts := strings.Split(hostPortPart, ":")
	port := parts[len(parts)-1]

	adminURL = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%s/postgres?sslmode=disable", port)
	apiURL = fmt.Sprintf("postgres://api_role:api_pass@127.0.0.1:%s/postgres?sslmode=disable", port)

	return adminURL, apiURL, cleanup
}

func TestHealthz(t *testing.T) {
	h := New(nil, nil)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	h.Healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	var res map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res["status"] != "ok" {
		t.Fatalf("expected status 'ok', got '%s'", res["status"])
	}
}

func TestSignerMetadata(t *testing.T) {
	h := New(nil, nil)

	// 1. Initial default metadata
	req := httptest.NewRequest("GET", "/v1/signer", nil)
	rec := httptest.NewRecorder()
	h.GetSigner(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	var meta SignerMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to decode signer metadata: %v", err)
	}
	if meta.SignerID != "signer-local-1" {
		t.Errorf("expected signer-local-1, got %s", meta.SignerID)
	}
	if meta.ProtectionLevel != "generic-dev" {
		t.Errorf("expected generic-dev, got %s", meta.ProtectionLevel)
	}
	if meta.Capabilities.Backend != "softhsm-generic" {
		t.Errorf("expected softhsm-generic, got %s", meta.Capabilities.Backend)
	}

	// 2. Dynamic update
	updated := meta
	updated.ProtectionLevel = "generic-hsm"
	h.SignerRegistry().Set(updated)

	rec2 := httptest.NewRecorder()
	h.GetSigner(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec2.Code)
	}
	var meta2 SignerMetadata
	_ = json.Unmarshal(rec2.Body.Bytes(), &meta2)
	if meta2.ProtectionLevel != "generic-hsm" {
		t.Errorf("expected generic-hsm after update, got %s", meta2.ProtectionLevel)
	}
}

func TestSubmitRequest_EnvelopeValidation(t *testing.T) {
	h := New(nil, nil)

	tests := []struct {
		name       string
		payload    any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty body",
			payload:    "",
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "missing body field",
			payload: map[string]any{
				"authorization": map[string]any{"kid": "k", "alg": "a", "sig": "s"},
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "missing authorization field",
			payload: map[string]any{
				"body": "eyJ2IjoxfQ",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "invalid authorization object (missing sig and jws)",
			payload: map[string]any{
				"body":          "eyJ2IjoxfQ",
				"authorization": map[string]any{"kid": "k", "alg": "a"},
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "invalid base64url body",
			payload: map[string]any{
				"body":          "not valid base64url!!!",
				"authorization": map[string]any{"kid": "k", "alg": "a", "sig": "s"},
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "unsupported envelope version (v=2)",
			payload: func() SubmitRequestEnvelope {
				b := makeTestRequestBody("", time.Now().Add(10*time.Minute))
				b.V = 2
				return encodeTestEnvelope(b, nil)
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "invalid request type",
			payload: func() SubmitRequestEnvelope {
				b := makeTestRequestBody("", time.Now().Add(10*time.Minute))
				b.Type = "destroy_world"
				return encodeTestEnvelope(b, nil)
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "invalid request_id (not uuid)",
			payload: func() SubmitRequestEnvelope {
				b := makeTestRequestBody("", time.Now().Add(10*time.Minute))
				b.RequestID = "not-a-uuid"
				return encodeTestEnvelope(b, nil)
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "expired request",
			payload: func() SubmitRequestEnvelope {
				b := makeTestRequestBody("", time.Now().Add(-1*time.Minute))
				return encodeTestEnvelope(b, nil)
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
		{
			name: "path depth exceeds 255",
			payload: func() SubmitRequestEnvelope {
				b := makeTestRequestBody("", time.Now().Add(10*time.Minute))
				deepPath := make([]uint32, 256)
				b.Path = deepPath
				return encodeTestEnvelope(b, nil)
			}(),
			wantStatus: http.StatusBadRequest,
			wantCode:   problem.CodeInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.SubmitRequest(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tc.wantStatus, rec.Code, rec.Body.String())
			}
			var prob problem.ProblemDetails
			if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
				t.Fatalf("failed to decode problem details: %v", err)
			}
			if prob.Code != tc.wantCode {
				t.Errorf("expected code '%s', got '%s'", tc.wantCode, prob.Code)
			}
		})
	}
}

func TestHandlersWithPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration test in short mode")
	}

	adminURL, apiURL, cleanup := setupTestPostgres(t)
	defer cleanup()

	// 1. Run migrations
	if err := db.RunMigrations(adminURL, ""); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// 2. Connect as api_role
	pool, err := db.Open(apiURL, db.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("failed to connect as api_role: %v", err)
	}
	defer pool.Close()

	h := New(pool, nil)

	// Context with authenticated client key
	clientKey := &auth.APIKey{
		ID:   uuid.New(),
		Name: "alice-test",
		Role: auth.RoleClient,
	}
	ctxWithAuth := auth.WithAPIKey(context.Background(), clientKey)

	// -------------------------------------------------------------
	// Test Wallets Routes: GET /v1/wallets and GET /v1/wallets/{id}
	// -------------------------------------------------------------
	t.Run("Wallets endpoints", func(t *testing.T) {
		// Empty wallets table check
		listReq := httptest.NewRequest("GET", "/v1/wallets", nil)
		listRec := httptest.NewRecorder()
		h.ListWallets(listRec, listReq)

		if listRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", listRec.Code)
		}
		var wallets []WalletMetadata
		_ = json.Unmarshal(listRec.Body.Bytes(), &wallets)
		if len(wallets) != 0 {
			t.Fatalf("expected 0 wallets, got %d", len(wallets))
		}

		// Insert a test wallet directly with sensitive fields
		const insertWallet = `
			INSERT INTO app.wallets (wallet_id, label, scheme, curve, seed_version, kek_label, wrapped_seed)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
		dummyWrappedSeed := []byte("secret_92_byte_wrapped_seed_blob_must_never_be_exposed_publicly")
		_, err := pool.Exec(insertWallet, "w_test_01", "Production Vault", "bip32", "secp256k1", 1, "kek-v1", dummyWrappedSeed)
		if err != nil {
			t.Fatalf("failed to insert test wallet: %v", err)
		}

		// List again: should contain 1 wallet and not leak wrapped_seed
		listRec2 := httptest.NewRecorder()
		h.ListWallets(listRec2, listReq)
		if listRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", listRec2.Code)
		}
		_ = json.Unmarshal(listRec2.Body.Bytes(), &wallets)
		if len(wallets) != 1 {
			t.Fatalf("expected 1 wallet, got %d", len(wallets))
		}
		if wallets[0].WalletID != "w_test_01" || wallets[0].Label != "Production Vault" {
			t.Errorf("unexpected wallet metadata: %+v", wallets[0])
		}
		// Confirm json payload contains no "wrapped_seed" key
		if strings.Contains(listRec2.Body.String(), "wrapped_seed") || strings.Contains(listRec2.Body.String(), "kek_label") {
			t.Fatalf("leaked sensitive wallet fields on GET /v1/wallets: %s", listRec2.Body.String())
		}

		// Get single existing wallet
		getReq := httptest.NewRequest("GET", "/v1/wallets/w_test_01", nil)
		getRec := httptest.NewRecorder()
		h.GetWallet(getRec, getReq, "w_test_01")
		if getRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", getRec.Code)
		}
		var single WalletMetadata
		_ = json.Unmarshal(getRec.Body.Bytes(), &single)
		if single.WalletID != "w_test_01" {
			t.Errorf("expected w_test_01, got %s", single.WalletID)
		}
		if strings.Contains(getRec.Body.String(), "wrapped_seed") {
			t.Fatalf("leaked wrapped_seed on GET /v1/wallets/{id}: %s", getRec.Body.String())
		}

		// Get non-existent wallet: 404 unknown_wallet
		getNotFoundRec := httptest.NewRecorder()
		h.GetWallet(getNotFoundRec, getReq, "w_non_existent")
		if getNotFoundRec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 Not Found, got %d", getNotFoundRec.Code)
		}
		var prob problem.ProblemDetails
		_ = json.Unmarshal(getNotFoundRec.Body.Bytes(), &prob)
		if prob.Code != problem.CodeUnknownWallet {
			t.Errorf("expected code unknown_wallet, got %s", prob.Code)
		}
	})

	// -------------------------------------------------------------
	// Test POST /v1/requests: submission, idempotency, audit log
	// -------------------------------------------------------------
	t.Run("POST /v1/requests submission and idempotency", func(t *testing.T) {
		reqID := uuid.New().String()
		expTime := time.Now().Add(10 * time.Minute)
		lbl := "my-new-wallet"
		env := encodeTestEnvelope(makeTestRequestBody(reqID, expTime), &lbl)
		rawEnv, _ := json.Marshal(env)

		// 1. First submission with Idempotency-Key
		postReq := httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawEnv)).WithContext(ctxWithAuth)
		postReq.Header.Set("Content-Type", "application/json")
		postReq.Header.Set("Idempotency-Key", "idemp-key-100")
		postRec := httptest.NewRecorder()

		h.SubmitRequest(postRec, postReq)

		if postRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d (body: %s)", postRec.Code, postRec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(postRec.Body.Bytes(), &resp)
		if resp["request_id"] != reqID {
			t.Errorf("expected request_id %s, got %v", reqID, resp["request_id"])
		}
		if resp["status"] != "ready" {
			t.Errorf("expected status ready, got %v", resp["status"])
		}

		// Verify audit log chain
		if err := db.VerifyAuditChain(context.Background(), pool); err != nil {
			t.Fatalf("audit chain verification failed after request submission: %v", err)
		}

		// 2. Second submission with the same Idempotency-Key: returns existing status
		postReq2 := httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawEnv)).WithContext(ctxWithAuth)
		postReq2.Header.Set("Content-Type", "application/json")
		postReq2.Header.Set("Idempotency-Key", "idemp-key-100")
		postRec2 := httptest.NewRecorder()

		h.SubmitRequest(postRec2, postReq2)

		if postRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on idempotent retry, got %d (body: %s)", postRec2.Code, postRec2.Body.String())
		}
		var resp2 map[string]any
		_ = json.Unmarshal(postRec2.Body.Bytes(), &resp2)
		if resp2["request_id"] != reqID || resp2["status"] != "ready" {
			t.Errorf("unexpected idempotent response: %+v", resp2)
		}

		// 3. Duplicate request_id without Idempotency-Key: returns 409 replayed
		postReq3 := httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawEnv)).WithContext(ctxWithAuth)
		postReq3.Header.Set("Content-Type", "application/json")
		postRec3 := httptest.NewRecorder()

		h.SubmitRequest(postRec3, postReq3)

		if postRec3.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict for duplicate request_id, got %d", postRec3.Code)
		}
		var prob problem.ProblemDetails
		_ = json.Unmarshal(postRec3.Body.Bytes(), &prob)
		if prob.Code != problem.CodeReplayed {
			t.Errorf("expected code replayed, got %s", prob.Code)
		}
	})

	// -------------------------------------------------------------
	// Test GET /v1/requests/{id} state transitions
	// -------------------------------------------------------------
	t.Run("GET /v1/requests/{id} lifecycle states", func(t *testing.T) {
		// A. Unknown request ID: 404
		unknownID := uuid.New().String()
		recA := httptest.NewRecorder()
		h.GetRequest(recA, httptest.NewRequest("GET", "/v1/requests/"+unknownID, nil), unknownID)
		if recA.Code != http.StatusNotFound {
			t.Fatalf("expected 404 Not Found, got %d", recA.Code)
		}

		// B. Ready status
		readyID := uuid.New().String()
		envReady := encodeTestEnvelope(makeTestRequestBody(readyID, time.Now().Add(10*time.Minute)), nil)
		rawReady, _ := json.Marshal(envReady)
		recReadySubmit := httptest.NewRecorder()
		h.SubmitRequest(recReadySubmit, httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawReady)).WithContext(ctxWithAuth))
		if recReadySubmit.Code != http.StatusAccepted {
			t.Fatalf("submit ready request failed: %d", recReadySubmit.Code)
		}

		recB := httptest.NewRecorder()
		h.GetRequest(recB, httptest.NewRequest("GET", "/v1/requests/"+readyID, nil), readyID)
		if recB.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for ready request, got %d", recB.Code)
		}
		var resB map[string]any
		_ = json.Unmarshal(recB.Body.Bytes(), &resB)
		if resB["status"] != "ready" || resB["request_id"] != readyID {
			t.Errorf("unexpected ready response: %+v", resB)
		}

		// C. Claimed status
		_, err := pool.Exec("UPDATE app.requests SET status = 'claimed', claimed_until = now() + interval '60s' WHERE request_id = $1", readyID)
		if err != nil {
			t.Fatalf("failed to update status to claimed: %v", err)
		}
		recC := httptest.NewRecorder()
		h.GetRequest(recC, httptest.NewRequest("GET", "/v1/requests/"+readyID, nil), readyID)
		if recC.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for claimed request, got %d", recC.Code)
		}
		var resC map[string]any
		_ = json.Unmarshal(recC.Body.Bytes(), &resC)
		if resC["status"] != "claimed" {
			t.Errorf("expected status claimed, got %v", resC["status"])
		}

		// D. Completed status with signed response
		completedID := uuid.New().String()
		envComp := encodeTestEnvelope(makeTestRequestBody(completedID, time.Now().Add(10*time.Minute)), nil)
		rawComp, _ := json.Marshal(envComp)
		h.SubmitRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawComp)).WithContext(ctxWithAuth))

		signedResult := map[string]any{
			"response": map[string]any{
				"request_id":       completedID,
				"decision_id":      "dec-test-123",
				"status":           "completed",
				"result":           map[string]any{"public_key": "02abcdef123456..."},
				"parsed":           map[string]any{"transfers": []any{}},
				"protection_level": "generic-dev",
				"backend":          "softhsm-generic",
				"signing_in_hsm":   true,
				"blind_sign":       false,
				"signed_at":        "2026-10-19T14:30:00Z",
			},
			"response_sig": hex.EncodeToString(make([]byte, 64)),
		}
		signedRaw, _ := json.Marshal(signedResult)
		_, err = pool.Exec("UPDATE app.requests SET status = 'completed', result = $1 WHERE request_id = $2", signedRaw, completedID)
		if err != nil {
			t.Fatalf("failed to update status to completed: %v", err)
		}

		recD := httptest.NewRecorder()
		h.GetRequest(recD, httptest.NewRequest("GET", "/v1/requests/"+completedID, nil), completedID)
		if recD.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for completed request, got %d", recD.Code)
		}
		var resD map[string]any
		_ = json.Unmarshal(recD.Body.Bytes(), &resD)
		if resD["status"] != "completed" {
			t.Errorf("expected completed status, got %v", resD["status"])
		}
		if resD["protection_level"] != "generic-dev" || resD["backend"] != "softhsm-generic" {
			t.Errorf("missing signer fields in completed response: %+v", resD)
		}
		if resD["signer_sig"] == "" {
			t.Errorf("missing signer_sig in completed response: %+v", resD)
		}

		// E. Dynamic expiration: ready request whose expires_at is now past
		pastExpID := uuid.New().String()
		envPast := encodeTestEnvelope(makeTestRequestBody(pastExpID, time.Now().Add(5*time.Second)), nil)
		rawPast, _ := json.Marshal(envPast)
		h.SubmitRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawPast)).WithContext(ctxWithAuth))
		// Set expires_at in the past
		_, _ = pool.Exec("UPDATE app.requests SET expires_at = now() - interval '5 seconds' WHERE request_id = $1", pastExpID)

		recE := httptest.NewRecorder()
		h.GetRequest(recE, httptest.NewRequest("GET", "/v1/requests/"+pastExpID, nil), pastExpID)
		if recE.Code != http.StatusGone {
			t.Fatalf("expected 410 Gone for dynamically expired request, got %d", recE.Code)
		}
		var probE problem.ProblemDetails
		_ = json.Unmarshal(recE.Body.Bytes(), &probE)
		if probE.Code != problem.CodeRequestExpired {
			t.Errorf("expected code request_expired, got %s", probE.Code)
		}

		// Confirm in DB that status was updated to 'expired'
		var statusInDB string
		_ = pool.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", pastExpID).Scan(&statusInDB)
		if statusInDB != "expired" {
			t.Errorf("expected DB status to be 'expired', got '%s'", statusInDB)
		}

		// F. Failed status with signer rejection reason: 422 signer_rejected
		failedID := uuid.New().String()
		envFail := encodeTestEnvelope(makeTestRequestBody(failedID, time.Now().Add(10*time.Minute)), nil)
		rawFail, _ := json.Marshal(envFail)
		h.SubmitRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawFail)).WithContext(ctxWithAuth))
		_, _ = pool.Exec("UPDATE app.requests SET status = 'failed', error_code = 'signature_invalid' WHERE request_id = $1", failedID)

		recF := httptest.NewRecorder()
		h.GetRequest(recF, httptest.NewRequest("GET", "/v1/requests/"+failedID, nil), failedID)
		if recF.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422 Unprocessable Entity for failed request, got %d", recF.Code)
		}
		var probF problem.ProblemDetails
		_ = json.Unmarshal(recF.Body.Bytes(), &probF)
		if probF.Code != problem.CodeSignerRejected {
			t.Errorf("expected code signer_rejected, got %s", probF.Code)
		}
		if probF.Reason != "signature_invalid" {
			t.Errorf("expected reason signature_invalid, got %s", probF.Reason)
		}

		// G. Failed status with replayed: 409 replayed
		replayedID := uuid.New().String()
		envRep := encodeTestEnvelope(makeTestRequestBody(replayedID, time.Now().Add(10*time.Minute)), nil)
		rawRep, _ := json.Marshal(envRep)
		h.SubmitRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/requests", bytes.NewReader(rawRep)).WithContext(ctxWithAuth))
		_, _ = pool.Exec("UPDATE app.requests SET status = 'failed', error_code = 'replayed' WHERE request_id = $1", replayedID)

		recG := httptest.NewRecorder()
		h.GetRequest(recG, httptest.NewRequest("GET", "/v1/requests/"+replayedID, nil), replayedID)
		if recG.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict for replayed failed request, got %d", recG.Code)
		}
		var probG problem.ProblemDetails
		_ = json.Unmarshal(recG.Body.Bytes(), &probG)
		if probG.Code != problem.CodeReplayed {
			t.Errorf("expected code replayed, got %s", probG.Code)
		}
	})
}
