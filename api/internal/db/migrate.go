package db

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations applies all pending SQL migrations using the administrative database connection string.
// migrationsSource can be a file URI (e.g. "file://migrations" or "file:///path/to/migrations") or a filesystem path.
func RunMigrations(adminDBURL string, migrationsSource string) error {
	if adminDBURL == "" {
		return errors.New("admin database URL cannot be empty")
	}

	sourceURL := resolveSourceURL(migrationsSource)

	m, err := migrate.New(sourceURL, adminDBURL)
	if err != nil {
		return fmt.Errorf("failed to initialize migration runner with source '%s': %w", sourceURL, err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		_ = srcErr
		_ = dbErr
	}()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			// Schema is already at the latest version
			return nil
		}
		return fmt.Errorf("failed to apply database migrations: %w", err)
	}

	return nil
}

// resolveSourceURL ensures the migrations source has a valid protocol prefix (e.g. "file://").
func resolveSourceURL(src string) string {
	if src == "" {
		// Walk up directory tree looking for a 'migrations' folder containing sql files
		if dir, err := os.Getwd(); err == nil {
			for i := 0; i < 6; i++ {
				cand := filepath.Join(dir, "migrations")
				if info, err := os.Stat(cand); err == nil && info.IsDir() {
					return "file://" + cand
				}
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				dir = parent
			}
		}
		return "file://migrations"
	}

	if strings.Contains(src, "://") {
		return src
	}

	abs, err := filepath.Abs(src)
	if err == nil {
		return "file://" + abs
	}
	return "file://" + src
}
