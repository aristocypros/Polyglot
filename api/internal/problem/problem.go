package problem

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Standard MIME types for RFC 9457 Problem Details.
const (
	ContentTypeProblemJSON = "application/problem+json"
)

// Standard RFC 9457 stable machine-readable error codes.
const (
	CodeInvalidRequest    = "invalid_request"
	CodeUnauthorized      = "unauthorized"
	CodeUnknownWallet     = "unknown_wallet"
	CodeRequestExpired    = "request_expired"
	CodeReplayed          = "replayed"
	CodeSignerRejected    = "signer_rejected"
	CodeSignerUnavailable = "signer_unavailable"
)

// ProblemDetails represents an RFC 9457 Problem Details object.
type ProblemDetails struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Status   int            `json:"status"`
	Detail   string         `json:"detail,omitempty"`
	Instance string         `json:"instance,omitempty"`
	Code     string         `json:"code"`
	Reason   string         `json:"reason,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// New creates a new ProblemDetails instance with default URI type.
func New(status int, code, title, detail string) ProblemDetails {
	return ProblemDetails{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Detail: detail,
		Code:   code,
	}
}

// Write writes a standard RFC 9457 Problem Details response to the ResponseWriter.
func Write(w http.ResponseWriter, status int, code, title, detail string) error {
	prob := New(status, code, title, detail)
	return WriteDetails(w, prob)
}

// WriteDetails serializes and sends a ProblemDetails struct as application/problem+json.
func WriteDetails(w http.ResponseWriter, prob ProblemDetails) error {
	if prob.Type == "" {
		prob.Type = "about:blank"
	}
	if prob.Status == 0 {
		prob.Status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", ContentTypeProblemJSON)
	w.WriteHeader(prob.Status)
	if err := json.NewEncoder(w).Encode(prob); err != nil {
		return fmt.Errorf("failed to encode problem details: %w", err)
	}
	return nil
}

// Convenience constructors for standard Polyglot errors:

// ErrUnauthorized returns a 401 Unauthorized problem details.
func ErrUnauthorized(detail string) ProblemDetails {
	return New(http.StatusUnauthorized, CodeUnauthorized, "Unauthorized", detail)
}

// ErrForbidden returns a 403 Forbidden problem details with code "unauthorized".
func ErrForbidden(detail string) ProblemDetails {
	return New(http.StatusForbidden, CodeUnauthorized, "Forbidden", detail)
}

// ErrInvalidRequest returns a 400 Bad Request problem details.
func ErrInvalidRequest(detail string) ProblemDetails {
	return New(http.StatusBadRequest, CodeInvalidRequest, "Invalid Request", detail)
}

// ErrUnknownWallet returns a 404 Not Found problem details.
func ErrUnknownWallet(detail string) ProblemDetails {
	return New(http.StatusNotFound, CodeUnknownWallet, "Unknown Wallet", detail)
}

// ErrRequestExpired returns a 410 Gone problem details.
func ErrRequestExpired(detail string) ProblemDetails {
	return New(http.StatusGone, CodeRequestExpired, "Request Expired", detail)
}

// ErrReplayed returns a 409 Conflict problem details.
func ErrReplayed(detail string) ProblemDetails {
	return New(http.StatusConflict, CodeReplayed, "Replayed Request", detail)
}

// ErrSignerRejected returns a 422 Unprocessable Entity problem details with a specific signer reason.
func ErrSignerRejected(reason, detail string) ProblemDetails {
	p := New(http.StatusUnprocessableEntity, CodeSignerRejected, "Signer Rejected", detail)
	p.Reason = reason
	return p
}

// ErrSignerUnavailable returns a 503 Service Unavailable problem details.
func ErrSignerUnavailable(detail string) ProblemDetails {
	return New(http.StatusServiceUnavailable, CodeSignerUnavailable, "Signer Unavailable", detail)
}
