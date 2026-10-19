package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	err := Write(rec, http.StatusUnauthorized, CodeUnauthorized, "Unauthorized", "Invalid bearer token")
	if err != nil {
		t.Fatalf("unexpected error writing problem: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != ContentTypeProblemJSON {
		t.Errorf("expected Content-Type %s, got %s", ContentTypeProblemJSON, contentType)
	}

	var prob ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("failed to decode problem JSON: %v", err)
	}

	if prob.Type != "about:blank" {
		t.Errorf("expected type 'about:blank', got '%s'", prob.Type)
	}
	if prob.Title != "Unauthorized" {
		t.Errorf("expected title 'Unauthorized', got '%s'", prob.Title)
	}
	if prob.Status != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, prob.Status)
	}
	if prob.Code != CodeUnauthorized {
		t.Errorf("expected code '%s', got '%s'", CodeUnauthorized, prob.Code)
	}
	if prob.Detail != "Invalid bearer token" {
		t.Errorf("expected detail 'Invalid bearer token', got '%s'", prob.Detail)
	}
}

func TestConvenienceErrors(t *testing.T) {
	tests := []struct {
		name       string
		prob       ProblemDetails
		wantStatus int
		wantCode   string
	}{
		{"Unauthorized", ErrUnauthorized("token invalid"), http.StatusUnauthorized, CodeUnauthorized},
		{"Forbidden", ErrForbidden("insufficient role"), http.StatusForbidden, CodeUnauthorized},
		{"InvalidRequest", ErrInvalidRequest("malformed envelope"), http.StatusBadRequest, CodeInvalidRequest},
		{"UnknownWallet", ErrUnknownWallet("wallet not found"), http.StatusNotFound, CodeUnknownWallet},
		{"RequestExpired", ErrRequestExpired("expired request"), http.StatusGone, CodeRequestExpired},
		{"Replayed", ErrReplayed("nonce already used"), http.StatusConflict, CodeReplayed},
		{"SignerRejected", ErrSignerRejected("bad_signature", "invalid sig"), http.StatusUnprocessableEntity, CodeSignerRejected},
		{"SignerUnavailable", ErrSignerUnavailable("no active signer"), http.StatusServiceUnavailable, CodeSignerUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := WriteDetails(rec, tt.prob); err != nil {
				t.Fatalf("WriteDetails failed: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
			if rec.Header().Get("Content-Type") != ContentTypeProblemJSON {
				t.Errorf("got content type %s, want %s", rec.Header().Get("Content-Type"), ContentTypeProblemJSON)
			}

			var parsed ProblemDetails
			if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("failed to parse json: %v", err)
			}
			if parsed.Code != tt.wantCode {
				t.Errorf("got code %s, want %s", parsed.Code, tt.wantCode)
			}
			if parsed.Status != tt.wantStatus {
				t.Errorf("got status %d, want %d", parsed.Status, tt.wantStatus)
			}
		})
	}
}
