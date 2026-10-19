package db

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestComputeAuditHashMatchesExpected(t *testing.T) {
	prevHash := GenesisPrevHash
	seq := int64(1)
	tsStr := "2026-10-19T12:00:00.123456Z"
	actor := "client-admin"
	event := "create_request"
	reqID := uuid.MustParse("0192a543-9b12-7890-abcd-ef0123456789")
	decisionID := "dec_01"

	// Calculate manually
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte("1"))
	h.Write([]byte(tsStr))
	h.Write([]byte(actor))
	h.Write([]byte(event))
	h.Write([]byte(reqID.String()))
	h.Write([]byte(decisionID))
	expected := hex.EncodeToString(h.Sum(nil))

	got := ComputeAuditHash(prevHash, seq, tsStr, actor, event, &reqID, &decisionID)
	if got != expected {
		t.Fatalf("ComputeAuditHash mismatch: got %s, want %s", got, expected)
	}

	entry := &AuditEntry{
		Seq:        seq,
		TS:         time.Date(2026, 10, 19, 12, 0, 0, 123456000, time.UTC),
		Actor:      actor,
		Event:      event,
		RequestID:  &reqID,
		DecisionID: &decisionID,
		PrevHash:   prevHash,
		Hash:       got,
	}

	entryHash := ComputeAuditEntryHash(entry)
	if entryHash != expected {
		t.Fatalf("ComputeAuditEntryHash mismatch: got %s, want %s", entryHash, expected)
	}
}

func TestFormatAuditTS(t *testing.T) {
	ts := time.Date(2026, 10, 19, 15, 30, 45, 123456789, time.UTC)
	// After truncating to microsecond:
	truncated := ts.Truncate(time.Microsecond)
	formatted := FormatAuditTS(truncated)

	want := "2026-10-19T15:30:45.123456Z"
	if formatted != want {
		t.Fatalf("FormatAuditTS mismatch: got %s, want %s", formatted, want)
	}
}

func TestAuditChainingSimulation(t *testing.T) {
	// Simulate 3 chained audit entries and verify chain calculation
	var entries []AuditEntry
	prevHash := GenesisPrevHash

	for i := int64(1); i <= 3; i++ {
		ts := time.Date(2026, 10, 19, 12, int(i), 0, 0, time.UTC)
		actor := "api"
		event := "test_event"
		reqID := uuid.New()
		hash := ComputeAuditHash(prevHash, i, FormatAuditTS(ts), actor, event, &reqID, nil)

		entries = append(entries, AuditEntry{
			Seq:       i,
			TS:        ts,
			Actor:     actor,
			Event:     event,
			RequestID: &reqID,
			PrevHash:  prevHash,
			Hash:      hash,
		})
		prevHash = hash
	}

	// Verify all entries link properly
	expectedPrev := GenesisPrevHash
	for i, entry := range entries {
		if entry.PrevHash != expectedPrev {
			t.Fatalf("entry %d prevHash mismatch: got %s, want %s", i, entry.PrevHash, expectedPrev)
		}
		expectedHash := ComputeAuditEntryHash(&entry)
		if entry.Hash != expectedHash {
			t.Fatalf("entry %d hash mismatch: got %s, want %s", i, entry.Hash, expectedHash)
		}
		expectedPrev = entry.Hash
	}

	if err := VerifyChainEntries(entries); err != nil {
		t.Fatalf("VerifyChainEntries failed on valid entries: %v", err)
	}

	// Tamper test 1: modified actor
	tamperedEntries := make([]AuditEntry, len(entries))
	copy(tamperedEntries, entries)
	tamperedEntries[1].Actor = "attacker"
	if err := VerifyChainEntries(tamperedEntries); err == nil {
		t.Errorf("expected error when verifying chain with modified actor")
	}

	// Tamper test 2: broken prev_hash link
	tamperedEntries2 := make([]AuditEntry, len(entries))
	copy(tamperedEntries2, entries)
	tamperedEntries2[2].PrevHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := VerifyChainEntries(tamperedEntries2); err == nil {
		t.Errorf("expected error when verifying chain with broken prev_hash link")
	}
}
