package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// GenesisPrevHash is the initial hash when the audit log table is empty (64 hex zeros).
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AppAuditAdvisoryLockID is the PostgreSQL transaction advisory lock ID used to serialize
// app.audit_log appends and prevent hash forks.
const AppAuditAdvisoryLockID = 742189420

// AuditEntry represents a row in app.audit_log.
type AuditEntry struct {
	Seq        int64      `json:"seq"`
	TS         time.Time  `json:"ts"`
	Actor      string     `json:"actor"`
	Event      string     `json:"event"`
	RequestID  *uuid.UUID `json:"request_id,omitempty"`
	DecisionID *string    `json:"decision_id,omitempty"`
	PrevHash   string     `json:"prev_hash"`
	Hash       string     `json:"hash"`
}

// FormatAuditTS formats a timestamp into RFC 3339 with microsecond precision to match PostgreSQL TIMESTAMPTZ.
func FormatAuditTS(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// ComputeAuditHash calculates SHA256(prev_hash || seq || ts || actor || event || request_id || decision_id).
func ComputeAuditHash(
	prevHash string,
	seq int64,
	tsStr string,
	actor string,
	event string,
	requestID *uuid.UUID,
	decisionID *string,
) string {
	hasher := sha256.New()
	hasher.Write([]byte(prevHash))
	hasher.Write([]byte(strconv.FormatInt(seq, 10)))
	hasher.Write([]byte(tsStr))
	hasher.Write([]byte(actor))
	hasher.Write([]byte(event))
	if requestID != nil {
		hasher.Write([]byte(requestID.String()))
	}
	if decisionID != nil && *decisionID != "" {
		hasher.Write([]byte(*decisionID))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// ComputeAuditEntryHash recalculates the cryptographic hash for a given AuditEntry.
func ComputeAuditEntryHash(entry *AuditEntry) string {
	return ComputeAuditHash(
		entry.PrevHash,
		entry.Seq,
		FormatAuditTS(entry.TS),
		entry.Actor,
		entry.Event,
		entry.RequestID,
		entry.DecisionID,
	)
}

// AppendAudit records a new immutable entry into app.audit_log within a new transaction.
func AppendAudit(
	ctx context.Context,
	db *sql.DB,
	actor string,
	event string,
	requestID *uuid.UUID,
	decisionID *string,
) (*AuditEntry, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin audit transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	entry, err := AppendAuditTx(ctx, tx, actor, event, requestID, decisionID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit audit transaction: %w", err)
	}

	return entry, nil
}

// AppendAuditTx records a new immutable entry into app.audit_log within an existing transaction.
func AppendAuditTx(
	ctx context.Context,
	tx *sql.Tx,
	actor string,
	event string,
	requestID *uuid.UUID,
	decisionID *string,
) (*AuditEntry, error) {
	// 1. Acquire PostgreSQL advisory xact lock to serialize audit appends and prevent hash forks
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", AppAuditAdvisoryLockID); err != nil {
		return nil, fmt.Errorf("failed to acquire audit advisory lock: %w", err)
	}

	// 2. Determine prev_hash from the latest audit row
	var prevHash string
	row := tx.QueryRowContext(ctx, "SELECT hash FROM app.audit_log ORDER BY seq DESC LIMIT 1")
	err := row.Scan(&prevHash)
	if err != nil {
		if err == sql.ErrNoRows {
			prevHash = GenesisPrevHash
		} else {
			return nil, fmt.Errorf("failed to query previous audit hash: %w", err)
		}
	}

	// 3. Fetch next monotonic sequence number
	var seq int64
	if err := tx.QueryRowContext(ctx, "SELECT nextval('app.audit_log_seq_seq')").Scan(&seq); err != nil {
		return nil, fmt.Errorf("failed to fetch next audit sequence: %w", err)
	}

	// 4. Capture timestamp truncated to microsecond precision matching TIMESTAMPTZ
	now := time.Now().UTC().Truncate(time.Microsecond)
	tsStr := FormatAuditTS(now)

	// 5. Compute cryptographic hash
	hash := ComputeAuditHash(prevHash, seq, tsStr, actor, event, requestID, decisionID)

	// 6. Insert audit row
	const insertSQL = `
		INSERT INTO app.audit_log (seq, ts, actor, event, request_id, decision_id, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	var reqIDVal any
	if requestID != nil {
		reqIDVal = *requestID
	}
	var decIDVal any
	if decisionID != nil && *decisionID != "" {
		decIDVal = *decisionID
	}

	if _, err := tx.ExecContext(ctx, insertSQL, seq, now, actor, event, reqIDVal, decIDVal, prevHash, hash); err != nil {
		return nil, fmt.Errorf("failed to insert audit row: %w", err)
	}

	return &AuditEntry{
		Seq:        seq,
		TS:         now,
		Actor:      actor,
		Event:      event,
		RequestID:  requestID,
		DecisionID: decisionID,
		PrevHash:   prevHash,
		Hash:       hash,
	}, nil
}

// FetchAuditEntries retrieves all audit rows in ascending sequence order.
func FetchAuditEntries(ctx context.Context, db *sql.DB, limit int) ([]AuditEntry, error) {
	query := "SELECT seq, ts, actor, event, request_id, decision_id, prev_hash, hash FROM app.audit_log ORDER BY seq ASC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var (
			entry      AuditEntry
			reqIDNull  uuid.NullUUID
			decIDNull  sql.NullString
		)
		if err := rows.Scan(
			&entry.Seq,
			&entry.TS,
			&entry.Actor,
			&entry.Event,
			&reqIDNull,
			&decIDNull,
			&entry.PrevHash,
			&entry.Hash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit row: %w", err)
		}
		if reqIDNull.Valid {
			entry.RequestID = &reqIDNull.UUID
		}
		if decIDNull.Valid {
			entry.DecisionID = &decIDNull.String
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading audit rows: %w", err)
	}

	return entries, nil
}

// VerifyAuditChain validates the cryptographic integrity of the entire audit hash chain.
func VerifyAuditChain(ctx context.Context, db *sql.DB) error {
	entries, err := FetchAuditEntries(ctx, db, 0)
	if err != nil {
		return err
	}
	return VerifyChainEntries(entries)
}

// VerifyChainEntries validates that a slice of AuditEntry items forms an unbroken, untampered cryptographic hash chain.
func VerifyChainEntries(entries []AuditEntry) error {
	expectedPrevHash := GenesisPrevHash
	for i, entry := range entries {
		// 1. Check prev_hash links to preceding entry
		if entry.PrevHash != expectedPrevHash {
			return fmt.Errorf("audit chain integrity violation at seq %d (index %d): expected prev_hash '%s', got '%s'",
				entry.Seq, i, expectedPrevHash, entry.PrevHash)
		}

		// 2. Verify current entry hash
		expectedHash := ComputeAuditEntryHash(&entry)
		if entry.Hash != expectedHash {
			return fmt.Errorf("audit chain hash mismatch at seq %d: expected hash '%s', stored '%s'",
				entry.Seq, expectedHash, entry.Hash)
		}

		expectedPrevHash = entry.Hash
	}

	return nil
}
