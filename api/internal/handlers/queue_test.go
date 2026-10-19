package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/auth"
	"polyglot/api/internal/db"
)

func TestWrappedSeedDecoding(t *testing.T) {
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc}

	// 1. Hex string without prefix
	hexStr := hex.EncodeToString(expected)
	b1, err := decodeWrappedSeed(hexStr)
	if err != nil || !bytes.Equal(b1, expected) {
		t.Fatalf("expected %x, got %x (err: %v)", expected, b1, err)
	}

	// 2. Hex string with 0x prefix
	b2, err := decodeWrappedSeed("0x" + hexStr)
	if err != nil || !bytes.Equal(b2, expected) {
		t.Fatalf("expected %x, got %x (err: %v)", expected, b2, err)
	}

	// 3. Raw byte slice
	b3, err := decodeWrappedSeed(expected)
	if err != nil || !bytes.Equal(b3, expected) {
		t.Fatalf("expected %x, got %x (err: %v)", expected, b3, err)
	}

	// 4. JSON float array
	anyArr := []any{float64(1), float64(2), float64(3), float64(4), float64(0xaa), float64(0xbb), float64(0xcc)}
	b4, err := decodeWrappedSeed(anyArr)
	if err != nil || !bytes.Equal(b4, expected) {
		t.Fatalf("expected %x, got %x (err: %v)", expected, b4, err)
	}

	// 5. Invalid format
	if _, err := decodeWrappedSeed("not-hex-or-b64!!!"); err == nil {
		t.Fatalf("expected error on invalid string, got nil")
	}
}

func TestQueueWithPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration test in short mode")
	}

	adminURL, apiURL, cleanup := setupTestPostgres(t)
	defer cleanup()

	if err := db.RunMigrations(adminURL, ""); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	dbConn, err := db.Open(apiURL, db.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("failed to open postgres connection: %v", err)
	}
	defer dbConn.Close()

	signerReg := NewSignerRegistry(nil)
	h := New(dbConn, signerReg)
	h.SetClaimPollParams(50*time.Millisecond, 200*time.Millisecond)

	authCtx := auth.WithAPIKey(context.Background(), &auth.APIKey{
		ID:   uuid.New(),
		Name: "signer-worker-1",
		Role: auth.RoleSigner,
	})

	clientCtx := auth.WithAPIKey(context.Background(), &auth.APIKey{
		ID:   uuid.New(),
		Name: "alice-client",
		Role: auth.RoleClient,
	})

	t.Run("Signer heartbeat updates signer registry", func(t *testing.T) {
		hb := SignerHeartbeat{
			SignerID:        "signer-node-42",
			PublicKey:       "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
			ProtectionLevel: "generic-hsm",
			Capabilities: &Capabilities{
				Backend:         "softhsm-generic",
				ProtectionLevel: "generic-hsm",
				Schemes: []SchemeCapability{
					{
						Scheme:       "bip32",
						Curve:        "secp256k1",
						HardenedOnly: false,
						Signing:      "hsm",
					},
				},
				MaxDepth:      100,
				WrapMechanism: "CKM_AES_GCM",
				DerivesInHSM:  false,
			},
		}

		hbBytes, _ := json.Marshal(hb)
		req := httptest.NewRequest(http.MethodPost, "/internal/claim", bytes.NewReader(hbBytes)).WithContext(authCtx)
		rec := httptest.NewRecorder()
		h.HandleInternalClaim(rec, req)

		if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
			t.Fatalf("expected 204 or 200, got %d", rec.Code)
		}

		meta, ok := signerReg.Get()
		if !ok || meta == nil {
			t.Fatalf("expected signer metadata to be present")
		}
		if meta.SignerID != "signer-node-42" {
			t.Errorf("expected signer_id 'signer-node-42', got '%s'", meta.SignerID)
		}
		if meta.PublicKey != hb.PublicKey {
			t.Errorf("expected public_key '%s', got '%s'", hb.PublicKey, meta.PublicKey)
		}
		if meta.ProtectionLevel != "generic-hsm" {
			t.Errorf("expected protection_level 'generic-hsm', got '%s'", meta.ProtectionLevel)
		}
	})

	t.Run("Concurrent claim calls (FOR UPDATE SKIP LOCKED) never double-claim", func(t *testing.T) {
		const numRequests = 20
		const numWorkers = 5

		reqIDs := make([]string, numRequests)
		for i := 0; i < numRequests; i++ {
			id := uuid.New().String()
			reqIDs[i] = id
			body := makeTestRequestBody(id, time.Now().Add(10*time.Minute))
			label := fmt.Sprintf("Vault-%d", i)
			env := encodeTestEnvelope(body, &label)
			envBytes, _ := json.Marshal(env)

			req := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
			rec := httptest.NewRecorder()
			h.SubmitRequest(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("failed to submit request %d: code %d, body: %s", i, rec.Code, rec.Body.String())
			}
		}

		// Launch concurrent workers claiming requests
		var mu sync.Mutex
		claimedIDs := make(map[string]int)
		var wg sync.WaitGroup

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for {
					req := httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx)
					rec := httptest.NewRecorder()
					h.HandleInternalClaim(rec, req)

					if rec.Code == http.StatusNoContent {
						// Queue drained
						break
					}
					if rec.Code != http.StatusOK {
						t.Errorf("worker %d got unexpected status %d: %s", workerID, rec.Code, rec.Body.String())
						break
					}

					var work ClaimedWork
					if err := json.NewDecoder(rec.Body).Decode(&work); err != nil {
						t.Errorf("worker %d failed to decode ClaimedWork: %v", workerID, err)
						break
					}

					mu.Lock()
					claimedIDs[work.RequestID]++
					mu.Unlock()
				}
			}(w)
		}

		wg.Wait()

		// Verify every request was claimed exactly once
		if len(claimedIDs) != numRequests {
			t.Fatalf("expected %d distinct requests claimed, got %d", numRequests, len(claimedIDs))
		}
		for reqID, count := range claimedIDs {
			if count != 1 {
				t.Errorf("request %s was claimed %d times (expected exactly 1)", reqID, count)
			}
		}
	})

	t.Run("Lease recovery reclaims 60-second expired leases to ready", func(t *testing.T) {
		id := uuid.New().String()
		body := makeTestRequestBody(id, time.Now().Add(10*time.Minute))
		label := "Lease-Test-Vault"
		env := encodeTestEnvelope(body, &label)
		envBytes, _ := json.Marshal(env)

		req := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		rec := httptest.NewRecorder()
		h.SubmitRequest(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", rec.Code)
		}

		// Claim it
		claimReq := httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx)
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, claimReq)
		if claimRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", claimRec.Code)
		}

		var work ClaimedWork
		_ = json.NewDecoder(claimRec.Body).Decode(&work)
		if work.RequestID != id {
			t.Fatalf("expected claimed request %s, got %s", id, work.RequestID)
		}

		// Verify in DB that it is claimed
		var status string
		var claimedUntil sql.NullTime
		err := dbConn.QueryRow("SELECT status, claimed_until FROM app.requests WHERE request_id = $1", id).Scan(&status, &claimedUntil)
		if err != nil || status != "claimed" || !claimedUntil.Valid {
			t.Fatalf("expected status 'claimed' with valid claimed_until, got status=%s, valid=%v", status, claimedUntil.Valid)
		}

		// Subsequent immediate claim returns 204 No Content
		claimRec2 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec2, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if claimRec2.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content on immediate claim, got %d", claimRec2.Code)
		}

		// Simulate 60-second lease expiry: set claimed_until in the past
		_, err = dbConn.Exec("UPDATE app.requests SET claimed_until = now() - interval '5 seconds' WHERE request_id = $1", id)
		if err != nil {
			t.Fatalf("failed to update claimed_until: %v", err)
		}

		// Claim again: ReclaimAndExpireRequests will reclaim lease to 'ready' and ClaimWorkOnce will re-claim it!
		claimRec3 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec3, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if claimRec3.Code != http.StatusOK {
			t.Fatalf("expected 200 OK after lease recovery, got %d (%s)", claimRec3.Code, claimRec3.Body.String())
		}

		var recoveredWork ClaimedWork
		_ = json.NewDecoder(claimRec3.Body).Decode(&recoveredWork)
		if recoveredWork.RequestID != id {
			t.Fatalf("expected recovered request %s, got %s", id, recoveredWork.RequestID)
		}
	})

	t.Run("Overdue requests transition to expired and are not claimed", func(t *testing.T) {
		id := uuid.New().String()
		body := makeTestRequestBody(id, time.Now().Add(10*time.Minute))
		env := encodeTestEnvelope(body, nil)
		envBytes, _ := json.Marshal(env)

		req := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		rec := httptest.NewRecorder()
		h.SubmitRequest(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", rec.Code)
		}

		// Simulate request expiring without being claimed
		_, err = dbConn.Exec("UPDATE app.requests SET expires_at = now() - interval '10 seconds' WHERE request_id = $1", id)
		if err != nil {
			t.Fatalf("failed to expire request in DB: %v", err)
		}

		// Claim call should expire overdue requests and find no work (204 No Content)
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if claimRec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content, got %d", claimRec.Code)
		}

		// Verify DB status is 'expired'
		var status string
		_ = dbConn.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", id).Scan(&status)
		if status != "expired" {
			t.Fatalf("expected status 'expired', got '%s'", status)
		}

		// Client query GET /v1/requests/{id} returns 410 request_expired
		getReq := httptest.NewRequest(http.MethodGet, "/v1/requests/"+id, nil)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, getReq, id)
		if getRec.Code != http.StatusGone {
			t.Fatalf("expected 410 Gone, got %d", getRec.Code)
		}
		if !strings.Contains(getRec.Body.String(), "request_expired") {
			t.Errorf("expected 'request_expired' in problem details, got %s", getRec.Body.String())
		}
	})

	t.Run("POST /internal/results completed create_wallet inserts wallet and appends audit log", func(t *testing.T) {
		reqID := uuid.New().String()
		walletID := "w_vault_" + reqID[:8]
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		body.WalletID = walletID
		label := "Enterprise Vault"
		env := encodeTestEnvelope(body, &label)
		envBytes, _ := json.Marshal(env)

		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", subRec.Code)
		}

		// Claim the request
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if claimRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", claimRec.Code)
		}

		// Signer completes create_wallet and posts to /internal/results
		wrappedSeedHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
		sigHex := "99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff"
		submission := SignerSubmission{
			RequestID: reqID,
			Status:    "completed",
			Response: map[string]any{
				"request_id":       reqID,
				"decision_id":      "dec-test-123",
				"request_hash":     "abcdef123456",
				"status":           "completed",
				"result":           map[string]any{"public_key": "02abcdef123456..."},
				"protection_level": "generic-dev",
				"backend":          "softhsm-generic",
				"signing_in_hsm":   true,
				"blind_sign":       false,
				"signed_at":        time.Now().UTC().Format(time.RFC3339),
			},
			ResponseSig: &sigHex,
			Wallet: &CreatedWalletData{
				WalletID:    walletID,
				Label:       label,
				Scheme:      "bip32",
				Curve:       "secp256k1",
				SeedVersion: 1,
				KekLabel:    "kek-v1",
				WrappedSeed: wrappedSeedHex,
			},
		}

		subData, _ := json.Marshal(submission)
		resReq := httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(subData)).WithContext(authCtx)
		resRec := httptest.NewRecorder()
		h.HandleInternalResults(resRec, resReq)

		if resRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on results, got %d: %s", resRec.Code, resRec.Body.String())
		}

		// 1. Verify app.wallets row exists
		var (
			storedLabel     string
			storedScheme    string
			storedCurve     string
			storedSeedVer   int
			storedKekLabel  string
			storedSeedBytes []byte
		)
		err := dbConn.QueryRow("SELECT label, scheme, curve, seed_version, kek_label, wrapped_seed FROM app.wallets WHERE wallet_id = $1", walletID).Scan(
			&storedLabel, &storedScheme, &storedCurve, &storedSeedVer, &storedKekLabel, &storedSeedBytes,
		)
		if err != nil {
			t.Fatalf("failed to query inserted wallet from app.wallets: %v", err)
		}
		if storedLabel != label || storedScheme != "bip32" || storedCurve != "secp256k1" {
			t.Errorf("unexpected wallet row: label=%s, scheme=%s, curve=%s", storedLabel, storedScheme, storedCurve)
		}
		if hex.EncodeToString(storedSeedBytes) != wrappedSeedHex {
			t.Errorf("wrapped_seed mismatch: expected %s, got %x", wrappedSeedHex, storedSeedBytes)
		}

		// 2. Verify app.requests row is completed
		var reqStatus string
		var reqResultRaw []byte
		err = dbConn.QueryRow("SELECT status, result FROM app.requests WHERE request_id = $1", reqID).Scan(&reqStatus, &reqResultRaw)
		if err != nil || reqStatus != "completed" {
			t.Fatalf("expected request status 'completed', got status=%s (err: %v)", reqStatus, err)
		}

		// 3. Verify GET /v1/requests/{id} returns completed result with signer_sig
		getReq := httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, getReq, reqID)
		if getRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from GET /v1/requests/{id}, got %d: %s", getRec.Code, getRec.Body.String())
		}
		var getResp map[string]any
		_ = json.NewDecoder(getRec.Body).Decode(&getResp)
		if getResp["status"] != "completed" {
			t.Errorf("expected status 'completed', got %v", getResp["status"])
		}
		if getResp["signer_sig"] != sigHex {
			t.Errorf("expected signer_sig '%s', got '%v'", sigHex, getResp["signer_sig"])
		}

		// 4. Verify GET /v1/wallets/{id} returns the new wallet
		wReq := httptest.NewRequest(http.MethodGet, "/v1/wallets/"+walletID, nil)
		wRec := httptest.NewRecorder()
		h.GetWallet(wRec, wReq, walletID)
		if wRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from GET /v1/wallets/{id}, got %d", wRec.Code)
		}

		// 5. Verify cryptographic audit chain integrity
		if err := db.VerifyAuditChain(context.Background(), dbConn); err != nil {
			t.Fatalf("audit chain verification failed: %v", err)
		}

		// 6. Test existing wallet inclusion in subsequent claim
		deriveReqID := uuid.New().String()
		deriveBody := makeTestRequestBody(deriveReqID, time.Now().Add(10*time.Minute))
		deriveBody.Type = "derive_public"
		deriveBody.WalletID = walletID
		deriveEnv := encodeTestEnvelope(deriveBody, nil)
		deriveData, _ := json.Marshal(deriveEnv)

		dReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(deriveData)).WithContext(clientCtx)
		dRec := httptest.NewRecorder()
		h.SubmitRequest(dRec, dReq)
		if dRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for derive_public, got %d", dRec.Code)
		}

		// Claim the derive_public request
		dClaimRec := httptest.NewRecorder()
		h.HandleInternalClaim(dClaimRec, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if dClaimRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", dClaimRec.Code)
		}
		var claimedDerive ClaimedWork
		_ = json.NewDecoder(dClaimRec.Body).Decode(&claimedDerive)
		if claimedDerive.Wallet == nil {
			t.Fatalf("expected wallet to be included in ClaimedWork for existing wallet_id, got nil")
		}
		if claimedDerive.Wallet.WalletID != walletID {
			t.Errorf("expected wallet_id %s, got %s", walletID, claimedDerive.Wallet.WalletID)
		}
		if claimedDerive.Wallet.WrappedSeed != wrappedSeedHex {
			t.Errorf("expected wrapped_seed %s, got %s", wrappedSeedHex, claimedDerive.Wallet.WrappedSeed)
		}
	})

	t.Run("POST /internal/results failed updates error_code and audit log", func(t *testing.T) {
		reqID := uuid.New().String()
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		env := encodeTestEnvelope(body, nil)
		envBytes, _ := json.Marshal(env)

		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", subRec.Code)
		}

		// Claim
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx))
		if claimRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", claimRec.Code)
		}

		// Post failed submission
		reason := "unsupported_transaction"
		submission := SignerSubmission{
			RequestID:  reqID,
			Status:     "failed",
			ReasonCode: &reason,
		}
		subData, _ := json.Marshal(submission)
		resReq := httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(subData)).WithContext(authCtx)
		resRec := httptest.NewRecorder()
		h.HandleInternalResults(resRec, resReq)

		if resRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on results, got %d: %s", resRec.Code, resRec.Body.String())
		}

		// Verify app.requests row has status='failed' and error_code='unsupported_transaction'
		var reqStatus string
		var reqErrCode sql.NullString
		err := dbConn.QueryRow("SELECT status, error_code FROM app.requests WHERE request_id = $1", reqID).Scan(&reqStatus, &reqErrCode)
		if err != nil || reqStatus != "failed" || !reqErrCode.Valid || reqErrCode.String != "unsupported_transaction" {
			t.Fatalf("expected status 'failed', error_code 'unsupported_transaction', got status=%s, err_code=%v", reqStatus, reqErrCode)
		}

		// Verify GET /v1/requests/{id} returns 422 signer_rejected with unsupported_transaction
		getReq := httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, getReq, reqID)
		if getRec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422 Unprocessable Entity, got %d: %s", getRec.Code, getRec.Body.String())
		}
		if !strings.Contains(getRec.Body.String(), "unsupported_transaction") {
			t.Errorf("expected 'unsupported_transaction' in problem details, got %s", getRec.Body.String())
		}

		// Verify audit chain
		if err := db.VerifyAuditChain(context.Background(), dbConn); err != nil {
			t.Fatalf("audit chain verification failed: %v", err)
		}
	})
}
