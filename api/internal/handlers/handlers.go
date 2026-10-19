package handlers

import (
	"database/sql"
	"time"
)

// Handler holds dependencies for the public HTTP route handlers.
type Handler struct {
	db                *sql.DB
	signerRegistry    *SignerRegistry
	claimPollInterval time.Duration
	claimPollTimeout  time.Duration
}

// New creates a new Handler instance.
func New(db *sql.DB, signerRegistry *SignerRegistry) *Handler {
	if signerRegistry == nil {
		signerRegistry = NewSignerRegistry(nil)
	}
	return &Handler{
		db:                db,
		signerRegistry:    signerRegistry,
		claimPollInterval: 1 * time.Second,
		claimPollTimeout:  25 * time.Second,
	}
}

// SignerRegistry returns the attached SignerRegistry.
func (h *Handler) SignerRegistry() *SignerRegistry {
	return h.signerRegistry
}

