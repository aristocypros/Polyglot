package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"polyglot/api/internal/problem"
)

// WalletMetadata represents the public non-sensitive wallet information.
type WalletMetadata struct {
	WalletID  string    `json:"wallet_id"`
	Label     string    `json:"label"`
	Scheme    string    `json:"scheme"`
	Curve     string    `json:"curve"`
	CreatedAt time.Time `json:"created_at"`
}

// HandleWallets dispatches requests under /v1/wallets and /v1/wallets/{id}.
func (h *Handler) HandleWallets(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/wallets")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		if r.Method == http.MethodGet {
			h.ListWallets(w, r)
			return
		}
		_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", "method not allowed on /v1/wallets")
		return
	}

	// Single wallet: path is the wallet ID
	if r.Method == http.MethodGet {
		h.GetWallet(w, r, path)
		return
	}

	_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", fmt.Sprintf("method %s not allowed on /v1/wallets/{id}", r.Method))
}

// ListWallets returns all wallets without exposing sensitive fields (wrapped_seed, kek_label, seed_version).
func (h *Handler) ListWallets(w http.ResponseWriter, r *http.Request) {
	wallets := make([]WalletMetadata, 0)

	if h.db != nil {
		const query = `
			SELECT wallet_id, label, scheme, curve, created_at
			FROM app.wallets
			ORDER BY created_at DESC
		`
		rows, err := h.db.QueryContext(r.Context(), query)
		if err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to query wallets")
			return
		}
		defer rows.Close()

		for rows.Next() {
			var wm WalletMetadata
			if err := rows.Scan(&wm.WalletID, &wm.Label, &wm.Scheme, &wm.Curve, &wm.CreatedAt); err != nil {
				_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to scan wallet row")
				return
			}
			wallets = append(wallets, wm)
		}
		if err := rows.Err(); err != nil {
			_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "error iterating wallet rows")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(wallets)
}

// GetWallet returns a single wallet's metadata by ID, or 404 unknown_wallet if not found.
func (h *Handler) GetWallet(w http.ResponseWriter, r *http.Request, walletID string) {
	if walletID == "" {
		_ = problem.WriteDetails(w, problem.ErrInvalidRequest("wallet ID cannot be empty"))
		return
	}

	if h.db == nil {
		_ = problem.WriteDetails(w, problem.ErrUnknownWallet(fmt.Sprintf("wallet '%s' not found", walletID)))
		return
	}

	const query = `
		SELECT wallet_id, label, scheme, curve, created_at
		FROM app.wallets
		WHERE wallet_id = $1
	`

	var wm WalletMetadata
	err := h.db.QueryRowContext(r.Context(), query, walletID).Scan(
		&wm.WalletID,
		&wm.Label,
		&wm.Scheme,
		&wm.Curve,
		&wm.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_ = problem.WriteDetails(w, problem.ErrUnknownWallet(fmt.Sprintf("wallet '%s' not found", walletID)))
			return
		}
		_ = problem.Write(w, http.StatusInternalServerError, problem.CodeInvalidRequest, "Internal Error", "failed to query wallet")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(wm)
}
