package db

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"polyglot/api/internal/auth"
)

func setupTestPostgres(t *testing.T) (adminURL, apiURL string, cleanup func()) {
	t.Helper()

	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found, skipping Postgres integration test")
		return "", "", func() {}
	}

	containerName := fmt.Sprintf("polyglot-pg-test-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "-d", "--name", containerName, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=postgres", "postgres:16")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("failed to start postgres container: %v (output: %s)", err, string(out))
		return "", "", func() {}
	}
	containerID := strings.TrimSpace(string(out))

	cleanup = func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	}

	// Wait for postgres to become ready
	ready := false
	for i := 0; i < 30; i++ {
		checkCmd := exec.Command("docker", "exec", containerID, "pg_isready", "-U", "postgres")
		if err := checkCmd.Run(); err == nil {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !ready {
		cleanup()
		t.Fatalf("postgres container failed to become ready in time")
	}

	// Determine host port
	portCmd := exec.Command("docker", "port", containerID, "5432")
	portOut, err := portCmd.CombinedOutput()
	if err != nil {
		cleanup()
		t.Fatalf("failed to get docker port: %v", err)
	}
	// Output format is e.g. "0.0.0.0:49153\n[::]:49153" or "127.0.0.1:49153"
	lines := strings.Split(strings.TrimSpace(string(portOut)), "\n")
	if len(lines) == 0 {
		cleanup()
		t.Fatalf("no port mapping found: %s", string(portOut))
	}
	hostPortPart := strings.TrimSpace(lines[0])
	parts := strings.Split(hostPortPart, ":")
	port := parts[len(parts)-1]

	adminURL = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%s/postgres?sslmode=disable", port)
	apiURL = fmt.Sprintf("postgres://api_role:api_pass@127.0.0.1:%s/postgres?sslmode=disable", port)

	return adminURL, apiURL, cleanup
}

func TestPostgresMigrationsAndAuditChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration test in short mode")
	}

	adminURL, apiURL, cleanup := setupTestPostgres(t)
	defer cleanup()

	// 1. Run migrations as admin
	t.Log("Applying database migrations with admin URL...")
	if err := RunMigrations(adminURL, ""); err != nil {
		t.Fatalf("RunMigrations failed: %v", err)
	}

	// Running migrations again should be a clean no-op (ErrNoChange handled)
	if err := RunMigrations(adminURL, ""); err != nil {
		t.Fatalf("Second RunMigrations call failed: %v", err)
	}

	// 2. Connect as runtime api_role
	t.Log("Connecting as runtime api_role...")
	apiDB, err := Open(apiURL, DefaultPoolConfig())
	if err != nil {
		t.Fatalf("failed to connect as api_role: %v", err)
	}
	defer apiDB.Close()

	ctx := context.Background()

	// 3. Test app.api_keys via DBKeyStore
	keyStore := auth.NewDBKeyStore(apiDB)

	clientToken := "client-secret-integration"
	signerToken := "signer-secret-integration"
	revokedToken := "revoked-secret-integration"

	clientHash := auth.HashToken(clientToken)
	signerHash := auth.HashToken(signerToken)
	revokedHash := auth.HashToken(revokedToken)

	// Insert test keys
	_, err = apiDB.ExecContext(ctx, `
		INSERT INTO app.api_keys (name, role, key_hash)
		VALUES ('client-app', 'client', $1), ('signer-node', 'signer', $2)
	`, clientHash, signerHash)
	if err != nil {
		t.Fatalf("failed to insert test api keys: %v", err)
	}

	_, err = apiDB.ExecContext(ctx, `
		INSERT INTO app.api_keys (name, role, key_hash, revoked_at)
		VALUES ('old-client', 'client', $1, now() - interval '1 hour')
	`, revokedHash)
	if err != nil {
		t.Fatalf("failed to insert revoked api key: %v", err)
	}

	// Test key lookups
	k1, err := keyStore.LookupKeyByHash(ctx, clientHash)
	if err != nil || k1 == nil || k1.Role != auth.RoleClient {
		t.Fatalf("expected active client key, got %+v (err: %v)", k1, err)
	}

	k2, err := keyStore.LookupKeyByHash(ctx, signerHash)
	if err != nil || k2 == nil || k2.Role != auth.RoleSigner {
		t.Fatalf("expected active signer key, got %+v (err: %v)", k2, err)
	}

	k3, err := keyStore.LookupKeyByHash(ctx, revokedHash)
	if err != nil {
		t.Fatalf("unexpected error querying revoked key: %v", err)
	}
	if k3 != nil {
		t.Fatalf("expected revoked key to return nil from LookupKeyByHash, got %+v", k3)
	}

	// 4. Test Hash-chained app.audit_log
	t.Log("Testing hash-chained audit log writes...")
	reqID1 := uuid.New()
	decID1 := "decision-101"

	// First audit entry (genesis)
	e1, err := AppendAudit(ctx, apiDB, "client-app", "request_created", &reqID1, &decID1)
	if err != nil {
		t.Fatalf("AppendAudit entry 1 failed: %v", err)
	}
	if e1.Seq != 1 {
		t.Errorf("expected seq 1, got %d", e1.Seq)
	}
	if e1.PrevHash != GenesisPrevHash {
		t.Errorf("expected genesis prev_hash %s, got %s", GenesisPrevHash, e1.PrevHash)
	}

	// Second audit entry (chained to e1)
	reqID2 := uuid.New()
	e2, err := AppendAudit(ctx, apiDB, "signer-node", "request_claimed", &reqID2, nil)
	if err != nil {
		t.Fatalf("AppendAudit entry 2 failed: %v", err)
	}
	if e2.Seq != 2 {
		t.Errorf("expected seq 2, got %d", e2.Seq)
	}
	if e2.PrevHash != e1.Hash {
		t.Errorf("expected e2 prev_hash %s, got %s", e1.Hash, e2.PrevHash)
	}

	// Third audit entry (chained to e2)
	decID3 := "decision-103"
	e3, err := AppendAudit(ctx, apiDB, "signer-node", "request_completed", &reqID2, &decID3)
	if err != nil {
		t.Fatalf("AppendAudit entry 3 failed: %v", err)
	}
	if e3.Seq != 3 {
		t.Errorf("expected seq 3, got %d", e3.Seq)
	}
	if e3.PrevHash != e2.Hash {
		t.Errorf("expected e3 prev_hash %s, got %s", e2.Hash, e3.PrevHash)
	}

	// Verify chain integrity passes
	if err := VerifyAuditChain(ctx, apiDB); err != nil {
		t.Fatalf("VerifyAuditChain failed on valid chain: %v", err)
	}

	// 5. Concurrent audit writes serialization test
	t.Log("Testing concurrent audit appends with advisory locking...")
	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			reqID := uuid.New()
			dec := fmt.Sprintf("dec-%d", workerID)
			_, err := AppendAudit(ctx, apiDB, fmt.Sprintf("worker-%d", workerID), "concurrent_event", &reqID, &dec)
			if err != nil {
				errCh <- fmt.Errorf("worker %d failed: %w", workerID, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent audit write error: %v", err)
	}

	// Verify the entire chain after 23 total appends
	entries, err := FetchAuditEntries(ctx, apiDB, 0)
	if err != nil {
		t.Fatalf("FetchAuditEntries failed: %v", err)
	}
	if len(entries) != 23 {
		t.Fatalf("expected 23 audit entries, found %d", len(entries))
	}

	if err := VerifyAuditChain(ctx, apiDB); err != nil {
		t.Fatalf("VerifyAuditChain failed after concurrent writes: %v", err)
	}

	// 6. Test audit log immutability (UPDATE and DELETE prohibited)
	t.Log("Testing immutability triggers on app.audit_log...")
	_, updateErr := apiDB.ExecContext(ctx, "UPDATE app.audit_log SET actor = 'tampered' WHERE seq = 1")
	if updateErr == nil {
		t.Fatalf("expected UPDATE on app.audit_log to fail, but it succeeded")
	}

	_, deleteErr := apiDB.ExecContext(ctx, "DELETE FROM app.audit_log WHERE seq = 1")
	if deleteErr == nil {
		t.Fatalf("expected DELETE on app.audit_log to fail, but it succeeded")
	}
}
