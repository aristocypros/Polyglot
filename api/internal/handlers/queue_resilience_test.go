package handlers

import (
	"bytes"
	"context"
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

// TestQueueResilience_Milestone5Gate tests Section 10's Queue row:
// 1. Two signer workers claiming concurrently against the API (exactly one claim per request, no double signing).
// 2. Signer killed mid-request before posting results: lease expires after timeout, second claim checks
//    signer.replay / signer.results (returns stored result if step 9 completed before crash, or marks failed
//    if crashed between step 5 and step 9).
// 3. Unclaimed request passing expires_at transitions cleanly to expired.
// 4. Full request lifecycle: POST /v1/requests -> /internal/claim -> /internal/results -> GET /v1/requests/{id}.
func TestQueueResilience_Milestone5Gate(t *testing.T) {
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

	adminConn, err := db.Open(adminURL, db.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("failed to open admin postgres connection: %v", err)
	}
	defer adminConn.Close()

	signerReg := NewSignerRegistry(nil)
	h := New(dbConn, signerReg)
	h.SetClaimPollParams(20*time.Millisecond, 100*time.Millisecond)

	authCtx1 := auth.WithAPIKey(context.Background(), &auth.APIKey{
		ID:   uuid.New(),
		Name: "signer-worker-1",
		Role: auth.RoleSigner,
	})

	authCtx2 := auth.WithAPIKey(context.Background(), &auth.APIKey{
		ID:   uuid.New(),
		Name: "signer-worker-2",
		Role: auth.RoleSigner,
	})

	clientCtx := auth.WithAPIKey(context.Background(), &auth.APIKey{
		ID:   uuid.New(),
		Name: "alice-client",
		Role: auth.RoleClient,
	})

	// -------------------------------------------------------------------------
	// 1. Two signer workers claiming concurrently against the API:
	//    (exactly one claim per request, no double signing)
	// -------------------------------------------------------------------------
	t.Run("Two signer workers claiming concurrently (no double signing)", func(t *testing.T) {
		const numRequests = 20
		createdReqIDs := make([]string, numRequests)

		for i := 0; i < numRequests; i++ {
			reqID := uuid.New().String()
			createdReqIDs[i] = reqID
			body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
			body.Nonce = strings.ReplaceAll(uuid.New().String(), "-", "")
			lbl := fmt.Sprintf("Concurrent-Vault-%d", i)
			env := encodeTestEnvelope(body, &lbl)
			envBytes, _ := json.Marshal(env)

			subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
			subRec := httptest.NewRecorder()
			h.SubmitRequest(subRec, subReq)
			if subRec.Code != http.StatusAccepted {
				t.Fatalf("request %d: expected 202 Accepted, got %d", i, subRec.Code)
			}
		}

		var claimsMu sync.Mutex
		claimedCount := make(map[string]int)
		signedCount := make(map[string]int)

		workerContexts := []context.Context{authCtx1, authCtx2}
		var wg sync.WaitGroup

		for wIdx, wCtx := range workerContexts {
			wg.Add(1)
			go func(workerID int, ctx context.Context) {
				defer wg.Done()
				for {
					claimRec := httptest.NewRecorder()
					claimReq := httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(ctx)
					h.HandleInternalClaim(claimRec, claimReq)

					if claimRec.Code == http.StatusNoContent {
						// Queue drained
						break
					}
					if claimRec.Code != http.StatusOK {
						t.Errorf("worker %d: unexpected claim status %d: %s", workerID, claimRec.Code, claimRec.Body.String())
						break
					}

					var work ClaimedWork
					if err := json.NewDecoder(claimRec.Body).Decode(&work); err != nil {
						t.Errorf("worker %d: failed to decode ClaimedWork: %v", workerID, err)
						break
					}

					claimsMu.Lock()
					claimedCount[work.RequestID]++
					claimsMu.Unlock()

					// Signer worker processes and submits result
					sigHex := fmt.Sprintf("sig-worker-%d-%s", workerID, work.RequestID)
					submission := SignerSubmission{
						RequestID: work.RequestID,
						Status:    "completed",
						Response: map[string]any{
							"request_id":       work.RequestID,
							"decision_id":      "dec-concurrent",
							"request_hash":     "abcdef",
							"status":           "completed",
							"result":           map[string]any{"public_key": "02abcdef..."},
							"protection_level": "generic-dev",
							"backend":          "softhsm-generic",
							"signing_in_hsm":   true,
							"blind_sign":       false,
							"signed_at":        time.Now().UTC().Format(time.RFC3339),
						},
						ResponseSig: &sigHex,
					}
					subData, _ := json.Marshal(submission)
					resRec := httptest.NewRecorder()
					resReq := httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(subData)).WithContext(ctx)
					h.HandleInternalResults(resRec, resReq)

					if resRec.Code != http.StatusOK {
						t.Errorf("worker %d: unexpected results status %d: %s", workerID, resRec.Code, resRec.Body.String())
					}

					claimsMu.Lock()
					signedCount[work.RequestID]++
					claimsMu.Unlock()
				}
			}(wIdx+1, wCtx)
		}

		wg.Wait()

		// Verify exactly one claim per request and exactly one completed submission
		if len(claimedCount) != numRequests {
			t.Fatalf("expected %d requests claimed, got %d", numRequests, len(claimedCount))
		}
		for _, reqID := range createdReqIDs {
			c := claimedCount[reqID]
			if c != 1 {
				t.Errorf("request %s was claimed %d times (expected exactly 1 claim)", reqID, c)
			}
			s := signedCount[reqID]
			if s != 1 {
				t.Errorf("request %s was signed %d times (expected exactly 1)", reqID, s)
			}

			// Verify status in DB is completed
			var status string
			err := dbConn.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", reqID).Scan(&status)
			if err != nil || status != "completed" {
				t.Errorf("request %s in DB: expected 'completed', got status=%s, err=%v", reqID, status, err)
			}
		}

		// Verify audit log chain
		if err := db.VerifyAuditChain(context.Background(), dbConn); err != nil {
			t.Fatalf("audit chain verification failed: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// 2. Signer killed mid-request before posting results:
	//    Part A: Step 9 completed before crash -> lease expires -> second claim
	//            finds stored result in signer.results and completes request.
	// -------------------------------------------------------------------------
	t.Run("Signer killed after Step 9: second claim returns stored result", func(t *testing.T) {
		reqID := uuid.New().String()
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		body.Nonce = strings.ReplaceAll(uuid.New().String(), "-", "")
		lbl := "Crash-Step9-Vault"
		env := encodeTestEnvelope(body, &lbl)
		envBytes, _ := json.Marshal(env)

		// Submit request
		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", subRec.Code)
		}

		// Worker 1 claims request
		claimRec1 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec1, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx1))
		if claimRec1.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", claimRec1.Code)
		}

		// Simulate Worker 1 executing Step 5 and Step 9:
		// Inserts into signer.replay AND signer.results before crash
		nonce := body.Nonce
		_, err := adminConn.Exec(`INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ($1, $2, now())`, reqID, nonce)
		if err != nil {
			t.Fatalf("failed to insert into signer.replay: %v", err)
		}

		respJSON := map[string]any{
			"request_id":       reqID,
			"decision_id":      "dec-crash-test",
			"request_hash":     "abcdef123",
			"status":           "completed",
			"result":           map[string]any{"public_key": "02abcdef12345678..."},
			"protection_level": "generic-dev",
			"backend":          "softhsm-generic",
			"signing_in_hsm":   true,
			"blind_sign":       false,
			"signed_at":        time.Now().UTC().Format(time.RFC3339),
		}
		respBytes, _ := json.Marshal(respJSON)
		const sigHex = "ed25519-sig-stored-step9"
		_, err = adminConn.Exec(`INSERT INTO signer.results (request_id, response, response_sig, created_at) VALUES ($1, $2, $3, now())`, reqID, respBytes, sigHex)
		if err != nil {
			t.Fatalf("failed to insert into signer.results: %v", err)
		}

		// Worker 1 crashes! (Never calls /internal/results)
		// Request remains 'claimed' in app.requests
		var curStatus string
		_ = dbConn.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", reqID).Scan(&curStatus)
		if curStatus != "claimed" {
			t.Fatalf("expected status 'claimed', got '%s'", curStatus)
		}

		// Simulate 60s lease timeout expiry
		_, err = dbConn.Exec("UPDATE app.requests SET claimed_until = now() - interval '1 second' WHERE request_id = $1", reqID)
		if err != nil {
			t.Fatalf("failed to expire lease: %v", err)
		}

		// Worker 2 calls /internal/claim: triggers reclaim of expired lease and claims it
		claimRec2 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec2, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx2))
		if claimRec2.Code != http.StatusOK {
			t.Fatalf("expected Worker 2 to claim request after lease expiry, got %d: %s", claimRec2.Code, claimRec2.Body.String())
		}

		var reclaimedWork ClaimedWork
		_ = json.NewDecoder(claimRec2.Body).Decode(&reclaimedWork)
		if reclaimedWork.RequestID != reqID {
			t.Fatalf("expected reclaimed work for request %s, got %s", reqID, reclaimedWork.RequestID)
		}

		// Worker 2 runs Step 5: queries signer.results, finds the stored result!
		var storedRespRaw []byte
		var storedSig string
		err = adminConn.QueryRow("SELECT response, response_sig FROM signer.results WHERE request_id = $1", reqID).Scan(&storedRespRaw, &storedSig)
		if err != nil {
			t.Fatalf("Worker 2 failed to fetch stored result: %v", err)
		}

		var cachedResp map[string]any
		_ = json.Unmarshal(storedRespRaw, &cachedResp)

		// Worker 2 posts the cached result to /internal/results
		sub2 := SignerSubmission{
			RequestID:   reqID,
			Status:      "completed",
			Response:    cachedResp,
			ResponseSig: &storedSig,
		}
		sub2Data, _ := json.Marshal(sub2)
		resRec2 := httptest.NewRecorder()
		h.HandleInternalResults(resRec2, httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(sub2Data)).WithContext(authCtx2))
		if resRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on posting cached results, got %d: %s", resRec2.Code, resRec2.Body.String())
		}

		// Verify app.requests now has status='completed'
		var finalStatus string
		_ = dbConn.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", reqID).Scan(&finalStatus)
		if finalStatus != "completed" {
			t.Fatalf("expected final status 'completed', got '%s'", finalStatus)
		}

		// Verify client GET /v1/requests/{id} returns 200 OK
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil), reqID)
		if getRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on GET request, got %d: %s", getRec.Code, getRec.Body.String())
		}
	})

	// -------------------------------------------------------------------------
	// 2. Signer killed mid-request before posting results:
	//    Part B: Crashed between Step 5 and Step 9 -> lease expires -> second claim
	//            checks signer.replay (seen) without signer.results -> marks failed.
	// -------------------------------------------------------------------------
	t.Run("Signer killed between Step 5 and Step 9: second claim marks failed (replayed)", func(t *testing.T) {
		reqID := uuid.New().String()
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		body.Nonce = strings.ReplaceAll(uuid.New().String(), "-", "")
		lbl := "Crash-Step5-Vault"
		env := encodeTestEnvelope(body, &lbl)
		envBytes, _ := json.Marshal(env)

		// Submit request
		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", subRec.Code)
		}

		// Worker 1 claims request
		claimRec1 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec1, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx1))
		if claimRec1.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on claim, got %d", claimRec1.Code)
		}

		// Simulate Worker 1 executing Step 5:
		// Inserts into signer.replay, but crashes BEFORE Step 9 (nothing in signer.results)
		nonce := body.Nonce
		_, err := adminConn.Exec(`INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ($1, $2, now())`, reqID, nonce)
		if err != nil {
			t.Fatalf("failed to insert into signer.replay: %v", err)
		}

		// Simulate lease expiry
		_, err = dbConn.Exec("UPDATE app.requests SET claimed_until = now() - interval '1 second' WHERE request_id = $1", reqID)
		if err != nil {
			t.Fatalf("failed to expire lease: %v", err)
		}

		// Worker 2 calls /internal/claim: reclaims request and returns it
		claimRec2 := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec2, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx2))
		if claimRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on reclaim, got %d", claimRec2.Code)
		}

		// Worker 2 runs Step 5:
		// 1. Checks signer.results -> not found.
		// 2. Checks signer.replay -> already present! (StoreError::Replayed / ProcessorError::Replayed)
		var resultCount int
		_ = adminConn.QueryRow("SELECT count(*) FROM signer.results WHERE request_id = $1", reqID).Scan(&resultCount)
		var replayCount int
		_ = adminConn.QueryRow("SELECT count(*) FROM signer.replay WHERE request_id = $1", reqID).Scan(&replayCount)

		if resultCount != 0 || replayCount != 1 {
			t.Fatalf("expected replay=1 and results=0, got replay=%d, results=%d", replayCount, resultCount)
		}

		// Worker 2 marks request as failed with error_code='replayed'
		errorCode := "replayed"
		reasonCode := "replayed"
		failedSub := SignerSubmission{
			RequestID:  reqID,
			Status:     "failed",
			ErrorCode:  &errorCode,
			ReasonCode: &reasonCode,
		}
		failedData, _ := json.Marshal(failedSub)
		resRec2 := httptest.NewRecorder()
		h.HandleInternalResults(resRec2, httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(failedData)).WithContext(authCtx2))
		if resRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on posting failed result, got %d: %s", resRec2.Code, resRec2.Body.String())
		}

		// Verify app.requests now has status='failed' and error_code='replayed'
		var finalStatus, finalErrCode string
		err = dbConn.QueryRow("SELECT status, COALESCE(error_code, '') FROM app.requests WHERE request_id = $1", reqID).Scan(&finalStatus, &finalErrCode)
		if err != nil || finalStatus != "failed" || finalErrCode != "replayed" {
			t.Fatalf("expected status 'failed', error_code 'replayed', got status=%s, err_code=%s", finalStatus, finalErrCode)
		}

		// Verify client GET /v1/requests/{id} returns 409 Conflict (replayed)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil), reqID)
		if getRec.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict, got %d: %s", getRec.Code, getRec.Body.String())
		}
		if !strings.Contains(getRec.Body.String(), "replayed") {
			t.Errorf("expected 'replayed' in problem details, got %s", getRec.Body.String())
		}
	})

	// -------------------------------------------------------------------------
	// 3. Unclaimed request passing expires_at transitions cleanly to expired
	// -------------------------------------------------------------------------
	t.Run("Unclaimed request passing expires_at transitions cleanly to expired", func(t *testing.T) {
		reqID := uuid.New().String()
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		lbl := "Expiring-Vault"
		env := encodeTestEnvelope(body, &lbl)
		envBytes, _ := json.Marshal(env)

		// Submit request
		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d", subRec.Code)
		}

		// Advance expires_at into the past
		_, err := dbConn.Exec("UPDATE app.requests SET expires_at = now() - interval '1 second' WHERE request_id = $1", reqID)
		if err != nil {
			t.Fatalf("failed to update expires_at: %v", err)
		}

		// Worker attempts to claim: ReclaimAndExpireRequests runs and transitions request to 'expired'
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx1))
		// The expired request is NOT claimed; claim returns 204 No Content
		if claimRec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content (expired request skipped), got %d: %s", claimRec.Code, claimRec.Body.String())
		}

		// Verify app.requests row has status='expired'
		var status string
		err = dbConn.QueryRow("SELECT status FROM app.requests WHERE request_id = $1", reqID).Scan(&status)
		if err != nil || status != "expired" {
			t.Fatalf("expected status 'expired', got status=%s, err=%v", status, err)
		}

		// Verify client GET /v1/requests/{id} returns 410 Gone (request_expired)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil), reqID)
		if getRec.Code != http.StatusGone {
			t.Fatalf("expected 410 Gone, got %d: %s", getRec.Code, getRec.Body.String())
		}
		if !strings.Contains(getRec.Body.String(), "request_expired") {
			t.Errorf("expected 'request_expired' in problem details, got %s", getRec.Body.String())
		}
	})

	// -------------------------------------------------------------------------
	// 4. Full request lifecycle:
	//    POST /v1/requests -> /internal/claim -> /internal/results -> GET /v1/requests/{id}
	// -------------------------------------------------------------------------
	t.Run("Full request lifecycle: submit -> claim -> results -> query", func(t *testing.T) {
		reqID := uuid.New().String()
		walletID := "w_e2e_" + reqID[:8]
		body := makeTestRequestBody(reqID, time.Now().Add(10*time.Minute))
		body.Nonce = strings.ReplaceAll(uuid.New().String(), "-", "")
		body.WalletID = walletID
		lbl := "Production Vault E2E"
		env := encodeTestEnvelope(body, &lbl)
		envBytes, _ := json.Marshal(env)

		// 1. POST /v1/requests
		subReq := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(envBytes)).WithContext(clientCtx)
		subRec := httptest.NewRecorder()
		h.SubmitRequest(subRec, subReq)
		if subRec.Code != http.StatusAccepted {
			t.Fatalf("POST /v1/requests: expected 202 Accepted, got %d: %s", subRec.Code, subRec.Body.String())
		}

		var submitResp map[string]any
		_ = json.NewDecoder(subRec.Body).Decode(&submitResp)
		if submitResp["status"] != "ready" {
			t.Errorf("expected initial status 'ready', got '%v'", submitResp["status"])
		}

		// 2. POST /internal/claim
		claimReq := httptest.NewRequest(http.MethodPost, "/internal/claim", nil).WithContext(authCtx1)
		claimRec := httptest.NewRecorder()
		h.HandleInternalClaim(claimRec, claimReq)
		if claimRec.Code != http.StatusOK {
			t.Fatalf("POST /internal/claim: expected 200 OK, got %d: %s", claimRec.Code, claimRec.Body.String())
		}

		var claimed ClaimedWork
		if err := json.NewDecoder(claimRec.Body).Decode(&claimed); err != nil {
			t.Fatalf("failed to decode ClaimedWork: %v", err)
		}
		if claimed.RequestID != reqID {
			t.Errorf("claimed request ID mismatch: expected %s, got %s", reqID, claimed.RequestID)
		}

		// 3. POST /internal/results
		sigHex := "e0f9b6a94b5f928e4e75d0f624dfbe1c8280f555c91f13885d56447c20c02111223344556677889900aabbccddeeff"
		wrappedSeedHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
		resultsSub := SignerSubmission{
			RequestID: reqID,
			Status:    "completed",
			Response: map[string]any{
				"request_id":       reqID,
				"decision_id":      body.DecisionID,
				"request_hash":     "hash-e2e-123",
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
				Label:       lbl,
				Scheme:      "bip32",
				Curve:       "secp256k1",
				SeedVersion: 1,
				KekLabel:    "kek-v1",
				WrappedSeed: wrappedSeedHex,
			},
		}
		subJSON, _ := json.Marshal(resultsSub)
		resReq := httptest.NewRequest(http.MethodPost, "/internal/results", bytes.NewReader(subJSON)).WithContext(authCtx1)
		resRec := httptest.NewRecorder()
		h.HandleInternalResults(resRec, resReq)
		if resRec.Code != http.StatusOK {
			t.Fatalf("POST /internal/results: expected 200 OK, got %d: %s", resRec.Code, resRec.Body.String())
		}

		// 4. GET /v1/requests/{id}
		getReq := httptest.NewRequest(http.MethodGet, "/v1/requests/"+reqID, nil)
		getRec := httptest.NewRecorder()
		h.GetRequest(getRec, getReq, reqID)
		if getRec.Code != http.StatusOK {
			t.Fatalf("GET /v1/requests/{id}: expected 200 OK, got %d: %s", getRec.Code, getRec.Body.String())
		}

		var queryResp map[string]any
		_ = json.NewDecoder(getRec.Body).Decode(&queryResp)
		if queryResp["status"] != "completed" {
			t.Errorf("expected query status 'completed', got '%v'", queryResp["status"])
		}
		if queryResp["request_id"] != reqID {
			t.Errorf("expected query request_id '%s', got '%v'", reqID, queryResp["request_id"])
		}
		if queryResp["signer_sig"] != sigHex {
			t.Errorf("expected signer_sig '%s', got '%v'", sigHex, queryResp["signer_sig"])
		}

		// Verify wallet was created in app.wallets
		var storedWalletID, storedLabel string
		err = dbConn.QueryRow("SELECT wallet_id, label FROM app.wallets WHERE wallet_id = $1", walletID).Scan(&storedWalletID, &storedLabel)
		if err != nil || storedWalletID != walletID || storedLabel != lbl {
			t.Fatalf("wallet not found in app.wallets: %v", err)
		}

		// Verify audit log chain passes verification
		if err := db.VerifyAuditChain(context.Background(), dbConn); err != nil {
			t.Fatalf("audit log integrity verification failed: %v", err)
		}
	})
}
