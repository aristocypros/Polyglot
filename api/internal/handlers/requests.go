package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/auth"
	"polyglot/api/internal/db"
	"polyglot/api/internal/problem"
)

// SubmitRequestEnvelope represents the envelope submitted to POST /v1/requests.
type SubmitRequestEnvelope struct {
	Body          string         `json:"body"`
	Authorization map[string]any `json:"authorization"`
	Label         *string        `json:"label,omitempty"`
}

// RequestBody represents the decoded canonical JSON body inside the envelope.
type RequestBody struct {
	V               int        `json:"v"`
	Type            string     `json:"type"`
	RequestID       string     `json:"request_id"`
	Nonce           string     `json:"nonce"`
	Audience        string     `json:"audience"`
	ExpiresAt       string     `json:"expires_at"`
	DecisionID      string     `json:"decision_id"`
	WalletID        string     `json:"wallet_id"`
	Scheme          string     `json:"scheme"`
	Curve           string     `json:"curve"`
	Path            []uint32   `json:"path,omitempty"`
	InputPaths      [][]uint32 `json:"input_paths,omitempty"`
	PayloadEncoding string     `json:"payload_encoding,omitempty"`
	Payload         string     `json:"payload,omitempty"`
	Chain           string     `json:"chain,omitempty"`
}

// RequestStatusResponse represents the JSON response for submitted or polling requests.
type RequestStatusResponse struct {
	RequestID       string    `json:"request_id"`
	Status          string    `json:"status"`
	ExpiresAt       time.Time `json:"expires_at"`
	Result          any       `json:"result,omitempty"`
	Parsed          any       `json:"parsed,omitempty"`
	ProtectionLevel string    `json:"protection_level,omitempty"`
	Backend         string    `json:"backend,omitempty"`
	SigningInHSM    *bool     `json:"signing_in_hsm,omitempty"`
	BlindSign       *bool     `json:"blind_sign,omitempty"`
	SignedAt        string    `json:"signed_at,omitempty"`
	SignerSig       string    `json:"signer_sig,omitempty"`
}

// HandleRequests dispatches requests under /v1/requests and /v1/requests/{id}.
func (h *Handler) HandleRequests(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/requests")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodPost:
			h.SubmitRequest(w, r)
		case http.MethodGet:
			h.ListRequests(w, r)
		default:
			_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", "method not allowed on /v1/requests")
		}
		return
	}

	// Single request by ID: /v1/requests/{id}
	if r.Method == http.MethodGet {
		h.GetRequest(w, r, path)
		return
	}

	_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", fmt.Sprintf("method %s not allowed on /v1/requests/{id}", r.Method))
}

// SubmitRequest handles POST /v1/requests.
func (h *Handler) SubmitRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce size limit (1MB max envelope size)
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("request body too large or unreadable"))
		return
	}

	var env SubmitRequestEnvelope
	if err := json.Unmarshal(bodyBytes, &env); err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid JSON envelope: "+err.Error()))
		return
	}

	// 2. Validate envelope shape
	if strings.TrimSpace(env.Body) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing body in envelope"))
		return
	}
	if env.Authorization == nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing authorization object in envelope"))
		return
	}

	// Validate authorization object fields: kid, alg, and sig/jws
	kid, _ := env.Authorization["kid"].(string)
	alg, _ := env.Authorization["alg"].(string)
	sig, _ := env.Authorization["sig"].(string)
	jws, _ := env.Authorization["jws"].(string)

	if strings.TrimSpace(kid) == "" || strings.TrimSpace(alg) == "" || (strings.TrimSpace(sig) == "" && strings.TrimSpace(jws) == "") {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid authorization: requires non-empty kid, alg, and sig or jws"))
		return
	}

	// 3. Base64url decode body
	canonicalBytes, err := base64.RawURLEncoding.DecodeString(env.Body)
	if err != nil {
		canonicalBytes, err = base64.URLEncoding.DecodeString(env.Body)
		if err != nil {
			_ = problem.WriteDetails(w, problem.ErrInvalidRequest("envelope body must be base64url encoded"))
			return
		}
	}

	// 4. Parse decoded canonical JSON body
	var reqBody RequestBody
	if err := json.Unmarshal(canonicalBytes, &reqBody); err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid canonical JSON body: "+err.Error()))
		return
	}

	// Envelope version
	if reqBody.V != 1 {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("unsupported envelope version: v must be 1"))
		return
	}

	// Request type
	switch reqBody.Type {
	case "create_wallet", "derive_public", "sign":
		// valid
	default:
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest(fmt.Sprintf("invalid request type '%s': must be create_wallet, derive_public, or sign", reqBody.Type)))
		return
	}

	// Request ID must be valid UUID
	reqUUID, err := uuid.Parse(reqBody.RequestID)
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid request_id in body: must be a valid UUID"))
		return
	}

	// Nonce
	if strings.TrimSpace(reqBody.Nonce) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing nonce in body"))
		return
	}

	// Audience
	if strings.TrimSpace(reqBody.Audience) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing audience in body"))
		return
	}

	// Decision ID
	if strings.TrimSpace(reqBody.DecisionID) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing decision_id in body"))
		return
	}

	// Wallet ID
	if strings.TrimSpace(reqBody.WalletID) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing wallet_id in body"))
		return
	}

	// Scheme & Curve
	if strings.TrimSpace(reqBody.Scheme) == "" || strings.TrimSpace(reqBody.Curve) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing scheme or curve in body"))
		return
	}

	// ExpiresAt
	if strings.TrimSpace(reqBody.ExpiresAt) == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("missing expires_at in body"))
		return
	}
	expTime, err := time.Parse(time.RFC3339Nano, reqBody.ExpiresAt)
	if err != nil {
		expTime, err = time.Parse(time.RFC3339, reqBody.ExpiresAt)
		if err != nil {
			_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid expires_at format: must be RFC 3339 timestamp"))
			return
		}
	}
	if time.Now().After(expTime) {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("request is already expired"))
		return
	}

	// Derivation path checks
	if len(reqBody.Path) > 255 {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("derivation path exceeds maximum depth of 255"))
		return
	}
	if reqBody.InputPaths != nil {
		for i, p := range reqBody.InputPaths {
			if len(p) > 255 {
				_ = problem.WriteDetails(w, problem.ErrInvalidRequest(fmt.Sprintf("input path at index %d exceeds maximum depth of 255", i)))
				return
			}
		}
	}

	// Optional unsigned label for create_wallet
	var labelVal string
	if env.Label != nil {
		if len(*env.Label) > 256 {
			_ = problem.WriteDetails(w, problem.ErrInvalidRequest("label exceeds maximum length of 256 characters"))
			return
		}
		labelVal = *env.Label
	}

	// 5. Idempotency Key check
	idempKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempKey != "" && h.db != nil {
		var existingReqID uuid.UUID
		var existingStatus string
		var existingExpiresAt time.Time

		const query = `
			SELECT request_id, status, expires_at
			FROM app.requests
			WHERE idempotency_key = $1
		`
		err := h.db.QueryRowContext(r.Context(), query, idempKey).Scan(&existingReqID, &existingStatus, &existingExpiresAt)
		if err == nil {
			// Idempotent hit: return existing request status
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": existingReqID.String(),
				"status":     existingStatus,
				"expires_at": existingExpiresAt.UTC().Format(time.RFC3339),
			})
			return
		} else if !errors.Is(err, sql.ErrNoRows) {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to check idempotency key")
			return
		}
	}

	// Compute body_hash (SHA-256 hex string over canonical body bytes)
	hasher := sha256.New()
	hasher.Write(canonicalBytes)
	bodyHash := hex.EncodeToString(hasher.Sum(nil))

	authJSON, err := json.Marshal(env.Authorization)
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("failed to serialize authorization object"))
		return
	}

	// 6. Insert request into app.requests and record hash-chained audit event
	if h.db != nil {
		tx, err := h.db.BeginTx(r.Context(), nil)
		if err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to begin transaction")
			return
		}
		defer func() {
			_ = tx.Rollback()
		}()

		var idempSQL sql.NullString
		if idempKey != "" {
			idempSQL = sql.NullString{String: idempKey, Valid: true}
		}

		const insertQuery = `
			INSERT INTO app.requests (
				request_id,
				idempotency_key,
				type,
				wallet_id,
				body_canonical,
				"authorization",
				label,
				body_hash,
				status,
				expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ready', $9)
		`

		_, err = tx.ExecContext(
			r.Context(),
			insertQuery,
			reqUUID,
			idempSQL,
			reqBody.Type,
			reqBody.WalletID,
			canonicalBytes,
			authJSON,
			labelVal,
			bodyHash,
			expTime,
		)
		if err != nil {
			// Handle unique constraint conflicts
			errMsg := err.Error()
			if strings.Contains(errMsg, "idempotency_key") {
				// Re-query existing request for idempotency collision
				var existingReqID uuid.UUID
				var existingStatus string
				var existingExpiresAt time.Time
				if queryErr := h.db.QueryRowContext(r.Context(), "SELECT request_id, status, expires_at FROM app.requests WHERE idempotency_key = $1", idempKey).Scan(&existingReqID, &existingStatus, &existingExpiresAt); queryErr == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"request_id": existingReqID.String(),
						"status":     existingStatus,
						"expires_at": existingExpiresAt.UTC().Format(time.RFC3339),
					})
					return
				}
			}
			if strings.Contains(errMsg, "requests_pkey") || strings.Contains(errMsg, "request_id") || strings.Contains(errMsg, "duplicate key") {
				_ = problem.WriteDetails(w, problem.ErrReplayed("request_id already submitted"))
				return
			}
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to insert request: "+err.Error())
			return
		}

		// Hash-chained audit event in app.audit_log
		actor := "client"
		if k, ok := auth.KeyFromContext(r.Context()); ok && k != nil && k.Name != "" {
			actor = k.Name
		}
		decisionID := reqBody.DecisionID
		if _, err := db.AppendAuditTx(r.Context(), tx, actor, "request_created", &reqUUID, &decisionID); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to record audit entry: "+err.Error())
			return
		}

		if err := tx.Commit(); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to commit request: "+err.Error())
			return
		}
	}

	// 7. Return 202 Accepted
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_id": reqUUID.String(),
		"status":     "ready",
		"expires_at": expTime.UTC().Format(time.RFC3339),
	})
}

// GetRequest handles GET /v1/requests/{id}.
func (h *Handler) GetRequest(w http.ResponseWriter, r *http.Request, reqIDStr string) {
	reqUUID, err := uuid.Parse(reqIDStr)
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid request_id: must be a valid UUID"))
		return
	}

	if h.db == nil {
		_ = problem.Write(w, http.StatusNotFound, "unknown_request", "Unknown Request", fmt.Sprintf("request '%s' not found", reqIDStr))
		return
	}

	ctx := r.Context()

	// 1. Mark expired if status == 'ready' and expires_at <= now()
	const expireQuery = `
		UPDATE app.requests
		SET status = 'expired'
		WHERE request_id = $1 AND status = 'ready' AND expires_at <= now()
	`
	_, _ = h.db.ExecContext(ctx, expireQuery, reqUUID)

	// 2. Fetch current request state
	const selectQuery = `
		SELECT request_id, status, expires_at, result, error_code
		FROM app.requests
		WHERE request_id = $1
	`

	var (
		resUUID      uuid.UUID
		resStatus    string
		resExpiresAt time.Time
		resResultRaw []byte
		resErrorCode sql.NullString
	)

	err = h.db.QueryRowContext(ctx, selectQuery, reqUUID).Scan(
		&resUUID,
		&resStatus,
		&resExpiresAt,
		&resResultRaw,
		&resErrorCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_ = problem.Write(w, http.StatusNotFound, "unknown_request", "Unknown Request", fmt.Sprintf("request '%s' not found", reqIDStr))
			return
		}
		_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to query request")
		return
	}

	// 3. Return appropriate response based on status
	switch resStatus {
	case "ready", "claimed":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_id": resUUID.String(),
			"status":     resStatus,
			"expires_at": resExpiresAt.UTC().Format(time.RFC3339),
		})

	case "completed":
		// Includes the signer's signed response (result, parsed, protection_level, backend, signing_in_hsm, blind_sign, signed_at, signer_sig)
		respPayload := map[string]any{
			"request_id": resUUID.String(),
			"status":     "completed",
			"expires_at": resExpiresAt.UTC().Format(time.RFC3339),
		}

		if len(resResultRaw) > 0 {
			var resultMap map[string]any
			if err := json.Unmarshal(resResultRaw, &resultMap); err == nil {
				// Handle both raw SignerResponse and nested { response, response_sig } formats
				if innerResp, ok := resultMap["response"].(map[string]any); ok {
					for k, v := range innerResp {
						respPayload[k] = v
					}
					if sig, ok := resultMap["response_sig"].(string); ok {
						respPayload["signer_sig"] = sig
					}
				} else {
					for k, v := range resultMap {
						respPayload[k] = v
					}
				}
				// Ensure signer_sig is populated if response_sig was used
				if _, hasSig := respPayload["signer_sig"]; !hasSig {
					if sig, ok := respPayload["response_sig"].(string); ok {
						respPayload["signer_sig"] = sig
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(respPayload)

	case "expired":
		_ = problem.WriteDetails(w, problem.ErrRequestExpired("request expired before being processed"))

	case "failed":
		errCode := "signer_rejected"
		if resErrorCode.Valid && resErrorCode.String != "" {
			errCode = resErrorCode.String
		}

		if errCode == "replayed" {
			_ = problem.WriteDetails(w, problem.ErrReplayed("request was already processed or replayed"))
			return
		}

		_ = problem.WriteDetails(w, problem.ErrSignerRejected(errCode, fmt.Sprintf("request was rejected by signer: %s", errCode)))

	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_id": resUUID.String(),
			"status":     resStatus,
			"expires_at": resExpiresAt.UTC().Format(time.RFC3339),
		})
	}
}

// ListRequests returns recent requests (for GET /v1/requests).
func (h *Handler) ListRequests(w http.ResponseWriter, r *http.Request) {
	requests := make([]map[string]any, 0)

	if h.db != nil {
		const query = `
			SELECT request_id, type, wallet_id, status, expires_at, created_at
			FROM app.requests
			ORDER BY created_at DESC
			LIMIT 100
		`
		rows, err := h.db.QueryContext(r.Context(), query)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var (
					reqID     uuid.UUID
					reqType   string
					walletID  string
					status    string
					expiresAt time.Time
					createdAt time.Time
				)
				if err := rows.Scan(&reqID, &reqType, &walletID, &status, &expiresAt, &createdAt); err == nil {
					requests = append(requests, map[string]any{
						"request_id": reqID.String(),
						"type":       reqType,
						"wallet_id":  walletID,
						"status":     status,
						"expires_at": expiresAt.UTC().Format(time.RFC3339),
						"created_at": createdAt.UTC().Format(time.RFC3339),
					})
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(requests)
}
