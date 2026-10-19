package handlers

import (
	"bytes"
	"context"
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

// SignerHeartbeat represents the optional payload sent by the signer on POST /internal/claim.
type SignerHeartbeat struct {
	SignerID        string        `json:"signer_id,omitempty"`
	PublicKey       string        `json:"public_key,omitempty"`
	Capabilities    *Capabilities `json:"capabilities,omitempty"`
	ProtectionLevel string        `json:"protection_level,omitempty"`
}

// ClaimedWallet represents the wallet metadata and wrapped seed returned in ClaimedWork.
type ClaimedWallet struct {
	WalletID    string `json:"wallet_id"`
	Label       string `json:"label"`
	Scheme      string `json:"scheme"`
	Curve       string `json:"curve"`
	SeedVersion uint32 `json:"seed_version"`
	KekLabel    string `json:"kek_label"`
	WrappedSeed string `json:"wrapped_seed"` // hex string
}

// ClaimedWork represents a claimed work item returned by POST /internal/claim.
type ClaimedWork struct {
	RequestID     string         `json:"request_id"`
	BodyCanonical string         `json:"body_canonical"`
	Authorization map[string]any `json:"authorization"`
	Label         *string        `json:"label,omitempty"`
	Wallet        *ClaimedWallet `json:"wallet,omitempty"`
}

// CreatedWalletData represents new wallet details submitted upon completed create_wallet.
type CreatedWalletData struct {
	WalletID    string `json:"wallet_id"`
	Label       string `json:"label"`
	Scheme      string `json:"scheme"`
	Curve       string `json:"curve"`
	SeedVersion uint32 `json:"seed_version"`
	KekLabel    string `json:"kek_label"`
	WrappedSeed any    `json:"wrapped_seed"` // hex string or byte array
}

// SignerSubmission represents the payload posted to POST /internal/results.
type SignerSubmission struct {
	RequestID   string             `json:"request_id"`
	Status      string             `json:"status"` // "completed" or "failed"
	Response    any                `json:"response,omitempty"`
	ResponseSig *string            `json:"response_sig,omitempty"`
	ErrorCode   *string            `json:"error_code,omitempty"`
	ReasonCode  *string            `json:"reason_code,omitempty"`
	Wallet      *CreatedWalletData `json:"wallet,omitempty"`
}

// decodeWrappedSeed parses wrapped seed bytes from hex string, base64 string, or byte array.
func decodeWrappedSeed(v any) ([]byte, error) {
	if v == nil {
		return nil, errors.New("missing wrapped_seed")
	}
	switch val := v.(type) {
	case string:
		clean := strings.TrimSpace(val)
		clean = strings.TrimPrefix(clean, "0x")
		if b, err := hex.DecodeString(clean); err == nil && len(clean)%2 == 0 {
			return b, nil
		}
		if b, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
			return b, nil
		}
		if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
			return b, nil
		}
		return nil, fmt.Errorf("invalid wrapped_seed string format")
	case []byte:
		return val, nil
	case []any:
		res := make([]byte, len(val))
		for i, el := range val {
			num, ok := el.(float64)
			if !ok {
				return nil, fmt.Errorf("invalid byte array item at index %d", i)
			}
			res[i] = byte(num)
		}
		return res, nil
	default:
		return nil, fmt.Errorf("unsupported wrapped_seed type %T", v)
	}
}

// SetClaimPollParams configures the short polling interval and maximum timeout for /internal/claim.
func (h *Handler) SetClaimPollParams(interval, timeout time.Duration) {
	h.claimPollInterval = interval
	h.claimPollTimeout = timeout
}

// updateSignerHeartbeat updates the SignerRegistry from heartbeat metadata.
func (h *Handler) updateSignerHeartbeat(hb SignerHeartbeat) {
	if hb.Capabilities == nil && hb.PublicKey == "" && hb.SignerID == "" {
		return
	}

	var meta SignerMetadata
	if cur, ok := h.signerRegistry.Get(); ok && cur != nil {
		meta = *cur
	} else {
		meta = DefaultSignerMetadata()
	}

	if hb.SignerID != "" {
		meta.SignerID = hb.SignerID
	}
	if hb.PublicKey != "" {
		meta.PublicKey = hb.PublicKey
	}
	if hb.ProtectionLevel != "" {
		meta.ProtectionLevel = hb.ProtectionLevel
	}
	if hb.Capabilities != nil {
		meta.Capabilities = *hb.Capabilities
		if hb.ProtectionLevel == "" && hb.Capabilities.ProtectionLevel != "" {
			meta.ProtectionLevel = hb.Capabilities.ProtectionLevel
		}
	}

	h.signerRegistry.Set(meta)
}

// ReclaimAndExpireRequests reclaims expired 60s leases and expires overdue requests.
func (h *Handler) ReclaimAndExpireRequests(ctx context.Context) error {
	if h.db == nil {
		return nil
	}

	const reclaimQuery = `
		UPDATE app.requests
		SET status = 'ready', claimed_until = NULL
		WHERE status = 'claimed' AND claimed_until < now() AND expires_at > now()
	`
	if _, err := h.db.ExecContext(ctx, reclaimQuery); err != nil {
		return fmt.Errorf("failed to reclaim expired leases: %w", err)
	}

	const expireQuery = `
		UPDATE app.requests
		SET status = 'expired', claimed_until = NULL
		WHERE status IN ('ready', 'claimed') AND expires_at <= now()
	`
	if _, err := h.db.ExecContext(ctx, expireQuery); err != nil {
		return fmt.Errorf("failed to expire overdue requests: %w", err)
	}

	return nil
}

// ClaimWorkOnce executes the exact FOR UPDATE SKIP LOCKED query to claim one ready request.
func (h *Handler) ClaimWorkOnce(ctx context.Context) (*ClaimedWork, error) {
	if h.db == nil {
		return nil, nil
	}

	const claimQuery = `
		UPDATE app.requests SET status = 'claimed', claimed_until = now() + interval '60 seconds'
		WHERE request_id = (
			SELECT request_id FROM app.requests
			WHERE status = 'ready' AND expires_at > now()
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING request_id, type, wallet_id, body_canonical, "authorization", label;
	`

	var (
		reqID         uuid.UUID
		reqType       string
		walletID      string
		bodyCanonical []byte
		authJSON      []byte
		label         sql.NullString
	)

	err := h.db.QueryRowContext(ctx, claimQuery).Scan(
		&reqID,
		&reqType,
		&walletID,
		&bodyCanonical,
		&authJSON,
		&label,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	var authMap map[string]any
	if err := json.Unmarshal(authJSON, &authMap); err != nil {
		authMap = make(map[string]any)
	}

	var labelPtr *string
	if label.Valid && label.String != "" {
		labelPtr = &label.String
	}

	var claimedWallet *ClaimedWallet
	const walletQuery = `
		SELECT wallet_id, label, scheme, curve, seed_version, kek_label, wrapped_seed
		FROM app.wallets
		WHERE wallet_id = $1
	`
	var (
		wID          string
		wLabel       string
		wScheme      string
		wCurve       string
		wSeedVersion uint32
		wKekLabel    string
		wWrappedSeed []byte
	)
	err = h.db.QueryRowContext(ctx, walletQuery, walletID).Scan(
		&wID,
		&wLabel,
		&wScheme,
		&wCurve,
		&wSeedVersion,
		&wKekLabel,
		&wWrappedSeed,
	)
	if err == nil {
		claimedWallet = &ClaimedWallet{
			WalletID:    wID,
			Label:       wLabel,
			Scheme:      wScheme,
			Curve:       wCurve,
			SeedVersion: wSeedVersion,
			KekLabel:    wKekLabel,
			WrappedSeed: hex.EncodeToString(wWrappedSeed),
		}
	}

	return &ClaimedWork{
		RequestID:     reqID.String(),
		BodyCanonical: string(bodyCanonical),
		Authorization: authMap,
		Label:         labelPtr,
		Wallet:        claimedWallet,
	}, nil
}

// HandleInternalClaim handles POST /internal/claim.
func (h *Handler) HandleInternalClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", "method not allowed on /internal/claim")
		return
	}

	// 1. Process optional signer heartbeat / capabilities registration
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
		if err == nil && len(bytes.TrimSpace(bodyBytes)) > 0 {
			var hb SignerHeartbeat
			if err := json.Unmarshal(bodyBytes, &hb); err == nil {
				h.updateSignerHeartbeat(hb)
			}
		}
	}

	if h.db == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 2. Short polling loop
	pollInterval := h.claimPollInterval
	if pollInterval <= 0 {
		pollInterval = 1 * time.Second
	}
	pollTimeout := h.claimPollTimeout
	if pollTimeout <= 0 {
		pollTimeout = 25 * time.Second
	}

	deadline := time.Now().Add(pollTimeout)

	for {
		// Reclaim expired leases and expire overdue requests
		if err := h.ReclaimAndExpireRequests(r.Context()); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to update request leases: "+err.Error())
			return
		}

		// Attempt to claim work
		work, err := h.ClaimWorkOnce(r.Context())
		if err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to claim work: "+err.Error())
			return
		}

		if work != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(work)
			return
		}

		// Check if time expired
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		sleepDur := pollInterval
		if sleepDur > remaining {
			sleepDur = remaining
		}

		select {
		case <-r.Context().Done():
			return
		case <-time.After(sleepDur):
		}
	}

	// No work arrived within timeout
	w.WriteHeader(http.StatusNoContent)
}

// HandleInternalResults handles POST /internal/results.
func (h *Handler) HandleInternalResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", "method not allowed on /internal/results")
		return
	}

	bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("request body too large or unreadable"))
		return
	}

	var sub SignerSubmission
	if err := json.Unmarshal(bodyBytes, &sub); err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid JSON submission: "+err.Error()))
		return
	}

	reqUUID, err := uuid.Parse(sub.RequestID)
	if err != nil {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid request_id in submission: must be a valid UUID"))
		return
	}

	if sub.Status != "completed" && sub.Status != "failed" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest(fmt.Sprintf("invalid status '%s': must be 'completed' or 'failed'", sub.Status)))
		return
	}

	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "request_id": reqUUID.String()})
		return
	}

	ctx := r.Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to begin transaction")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var (
		curStatus     string
		reqType       string
		bodyCanonical []byte
		reqLabel      sql.NullString
	)

	const selectReqSQL = `
		SELECT status, type, body_canonical, label
		FROM app.requests
		WHERE request_id = $1
		FOR UPDATE
	`
	err = tx.QueryRowContext(ctx, selectReqSQL, reqUUID).Scan(&curStatus, &reqType, &bodyCanonical, &reqLabel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_ = problem.Write(w, http.StatusNotFound, "unknown_request", "Unknown Request", fmt.Sprintf("request '%s' not found", sub.RequestID))
			return
		}
		_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to query request: "+err.Error())
		return
	}

	if curStatus == "completed" {
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "request_id": reqUUID.String()})
		return
	}

	// Extract decision_id if available
	var decIDPtr *string
	var bMap map[string]any
	if err := json.Unmarshal(bodyCanonical, &bMap); err == nil {
		if d, ok := bMap["decision_id"].(string); ok && d != "" {
			decIDPtr = &d
		}
	}

	actor := "signer"
	if k, ok := auth.KeyFromContext(ctx); ok && k != nil && k.Name != "" {
		actor = k.Name
	}

	if sub.Status == "completed" {
		// 1. If create_wallet, insert wallet into app.wallets
		if reqType == "create_wallet" && sub.Wallet != nil {
			seedBytes, err := decodeWrappedSeed(sub.Wallet.WrappedSeed)
			if err != nil {
				_ = problem.WriteDetails(w, problem.ErrInvalidRequest("invalid wrapped_seed in wallet data: "+err.Error()))
				return
			}
			wID := sub.Wallet.WalletID
			if wID == "" {
				if wid, ok := bMap["wallet_id"].(string); ok {
					wID = wid
				}
			}
			wScheme := sub.Wallet.Scheme
			if wScheme == "" {
				if s, ok := bMap["scheme"].(string); ok {
					wScheme = s
				}
			}
			wCurve := sub.Wallet.Curve
			if wCurve == "" {
				if c, ok := bMap["curve"].(string); ok {
					wCurve = c
				}
			}
			wLabel := sub.Wallet.Label
			if wLabel == "" && reqLabel.Valid {
				wLabel = reqLabel.String
			}
			wSeedVer := sub.Wallet.SeedVersion
			if wSeedVer == 0 {
				wSeedVer = 1
			}
			wKek := sub.Wallet.KekLabel
			if wKek == "" {
				wKek = "kek-v1"
			}

			const insertWalletSQL = `
				INSERT INTO app.wallets (
					wallet_id,
					label,
					scheme,
					curve,
					seed_version,
					kek_label,
					wrapped_seed
				) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (wallet_id) DO UPDATE SET
					label = EXCLUDED.label,
					wrapped_seed = EXCLUDED.wrapped_seed,
					kek_label = EXCLUDED.kek_label,
					seed_version = EXCLUDED.seed_version
			`
			if _, err := tx.ExecContext(ctx, insertWalletSQL,
				wID,
				wLabel,
				wScheme,
				wCurve,
				wSeedVer,
				wKek,
				seedBytes,
			); err != nil {
				_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to insert wallet: "+err.Error())
				return
			}
		}

		// 2. Prepare result payload
		resultMap := make(map[string]any)
		if sub.Response != nil {
			if m, ok := sub.Response.(map[string]any); ok {
				for k, v := range m {
					resultMap[k] = v
				}
			} else {
				raw, _ := json.Marshal(sub.Response)
				_ = json.Unmarshal(raw, &resultMap)
			}
		}
		if sub.ResponseSig != nil && *sub.ResponseSig != "" {
			resultMap["response_sig"] = *sub.ResponseSig
			resultMap["signer_sig"] = *sub.ResponseSig
		}
		resultJSON, err := json.Marshal(resultMap)
		if err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to serialize result: "+err.Error())
			return
		}

		// 3. Update app.requests
		const updateReqSQL = `
			UPDATE app.requests
			SET status = 'completed', result = $2, claimed_until = NULL
			WHERE request_id = $1
		`
		if _, err := tx.ExecContext(ctx, updateReqSQL, reqUUID, resultJSON); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to update request: "+err.Error())
			return
		}

		// 4. Append audit log
		if _, err := db.AppendAuditTx(ctx, tx, actor, "request_completed", &reqUUID, decIDPtr); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to record audit entry: "+err.Error())
			return
		}

	} else { // sub.Status == "failed"
		errCode := "signer_rejected"
		if sub.ReasonCode != nil && *sub.ReasonCode != "" {
			errCode = *sub.ReasonCode
		} else if sub.ErrorCode != nil && *sub.ErrorCode != "" {
			errCode = *sub.ErrorCode
		}

		const updateReqSQL = `
			UPDATE app.requests
			SET status = 'failed', error_code = $2, claimed_until = NULL
			WHERE request_id = $1
		`
		if _, err := tx.ExecContext(ctx, updateReqSQL, reqUUID, errCode); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to update request: "+err.Error())
			return
		}

		if _, err := db.AppendAuditTx(ctx, tx, actor, "request_failed", &reqUUID, decIDPtr); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to record audit entry: "+err.Error())
			return
		}
	}

	if err := tx.Commit(); err != nil {
		_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to commit transaction: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "request_id": reqUUID.String()})
}
