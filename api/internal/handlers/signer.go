package handlers

import (
	"encoding/json"
	"net/http"
	"sync"

	"polyglot/api/internal/problem"
)

// SchemeCapability defines per-curve and scheme capabilities supported by the signer backend.
type SchemeCapability struct {
	Scheme       string `json:"scheme"`
	Curve        string `json:"curve"`
	HardenedOnly bool   `json:"hardened_only"`
	Signing      string `json:"signing"`
}

// Capabilities represents the probed capabilities of the signer backend.
type Capabilities struct {
	Backend         string             `json:"backend"`
	ProtectionLevel string             `json:"protection_level"`
	Schemes         []SchemeCapability `json:"schemes"`
	MaxDepth        uint8              `json:"max_depth"`
	WrapMechanism   string             `json:"wrap_mechanism"`
	DerivesInHSM    bool               `json:"derives_in_hsm"`
}

// SignerMetadata represents the public metadata published on GET /v1/signer.
type SignerMetadata struct {
	SignerID        string       `json:"signer_id"`
	PublicKey       string       `json:"public_key"`
	Capabilities    Capabilities `json:"capabilities"`
	ProtectionLevel string       `json:"protection_level"`
}

// DefaultSignerMetadata returns a baseline generic-dev signer configuration.
func DefaultSignerMetadata() SignerMetadata {
	return SignerMetadata{
		SignerID:        "signer-local-1",
		PublicKey:       "e0f9b6a94b5f928e4e75d0f624dfbe1c8280f555c91f13885d56447c20c02111",
		ProtectionLevel: "generic-dev",
		Capabilities: Capabilities{
			Backend:         "softhsm-generic",
			ProtectionLevel: "generic-dev",
			Schemes: []SchemeCapability{
				{
					Scheme:       "bip32",
					Curve:        "secp256k1",
					HardenedOnly: false,
					Signing:      "hsm",
				},
				{
					Scheme:       "slip10",
					Curve:        "ed25519",
					HardenedOnly: true,
					Signing:      "hsm",
				},
			},
			MaxDepth:      255,
			WrapMechanism: "CKM_AES_GCM",
			DerivesInHSM:  false,
		},
	}
}

// SignerRegistry manages the cached / registered signer metadata in a thread-safe manner.
type SignerRegistry struct {
	mu   sync.RWMutex
	meta *SignerMetadata
}

// NewSignerRegistry creates a new SignerRegistry with optional initial metadata.
func NewSignerRegistry(initial *SignerMetadata) *SignerRegistry {
	if initial == nil {
		def := DefaultSignerMetadata()
		initial = &def
	}
	return &SignerRegistry{
		meta: initial,
	}
}

// Get retrieves the current signer metadata, if any.
func (r *SignerRegistry) Get() (*SignerMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.meta == nil {
		return nil, false
	}
	cp := *r.meta
	return &cp, true
}

// Set updates the registered signer metadata.
func (r *SignerRegistry) Set(meta SignerMetadata) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := meta
	r.meta = &cp
}

// GetSigner handles GET /v1/signer requests.
func (h *Handler) GetSigner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		_ = problem.Write(w, http.StatusMethodNotAllowed, problem.CodeInvalidRequest, "Method Not Allowed", "method not allowed on /v1/signer")
		return
	}

	meta, ok := h.signerRegistry.Get()
	if !ok || meta == nil {
		_ = problem.WriteDetails(w, problem.ErrSignerUnavailable("no signer currently registered or available"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(meta)
}
