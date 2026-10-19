package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"polyglot/api/internal/auth"
	"polyglot/api/internal/db"
	"polyglot/api/internal/server"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func readSecretFile(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func getSecretOrEnv(fileEnvKey, defaultFile, envKey, defaultVal string) string {
	filePath := getEnv(fileEnvKey, defaultFile)
	if secret := readSecretFile(filePath); secret != "" {
		return secret
	}
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	log.Println("Starting Polyglot API Server Foundation...")

	// 1. Load configuration from environment & secrets
	publicAddr := getEnv("PUBLIC_ADDR", ":8080")
	if p := os.Getenv("PORT"); p != "" {
		publicAddr = ":" + p
	}
	internalAddr := getEnv("INTERNAL_ADDR", ":8081")

	adminPass := getSecretOrEnv("ADMIN_DB_PASSWORD_FILE", "/run/secrets/db_admin_password", "ADMIN_DB_PASSWORD", "")
	apiPass := getSecretOrEnv("API_DB_PASSWORD_FILE", "/run/secrets/db_api_password", "API_DB_PASSWORD", "api_pass")
	signerPass := getSecretOrEnv("SIGNER_DB_PASSWORD_FILE", "/run/secrets/db_signer_password", "SIGNER_DB_PASSWORD", "signer_pass")
	clientAPIKey := getSecretOrEnv("CLIENT_API_KEY_FILE", "/run/secrets/client_api_key", "CLIENT_API_KEY", "")
	signerToken := getSecretOrEnv("SIGNER_TOKEN_FILE", "/run/secrets/signer_token", "SIGNER_TOKEN", "")

	adminDBURL := os.Getenv("ADMIN_DATABASE_URL")
	if adminDBURL == "" && adminPass != "" {
		pgHost := getEnv("POSTGRES_HOST", "postgres")
		pgPort := getEnv("POSTGRES_PORT", "5432")
		pgDB := getEnv("POSTGRES_DB", "postgres")
		adminDBURL = fmt.Sprintf("postgres://postgres:%s@%s:%s/%s?sslmode=disable", adminPass, pgHost, pgPort, pgDB)
	}

	runtimeDBURL := os.Getenv("DATABASE_URL")
	if runtimeDBURL == "" {
		if os.Getenv("POSTGRES_HOST") != "" {
			pgHost := getEnv("POSTGRES_HOST", "postgres")
			pgPort := getEnv("POSTGRES_PORT", "5432")
			pgDB := getEnv("POSTGRES_DB", "postgres")
			runtimeDBURL = fmt.Sprintf("postgres://api_role:%s@%s:%s/%s?sslmode=disable", apiPass, pgHost, pgPort, pgDB)
		} else {
			runtimeDBURL = fmt.Sprintf("postgres://api_role:%s@127.0.0.1:5432/postgres?sslmode=disable", apiPass)
		}
	}

	migrationsPath := getEnv("MIGRATIONS_PATH", "")

	// 2. Run migrations if admin connection string provided
	if adminDBURL != "" {
		log.Printf("Connecting to administrative database to run migrations...")
		var adminDB *sql.DB
		var err error
		for attempt := 1; attempt <= 30; attempt++ {
			adminDB, err = sql.Open("pgx", adminDBURL)
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err = adminDB.PingContext(ctx)
				cancel()
				if err == nil {
					break
				}
				adminDB.Close()
			}
			log.Printf("Waiting for postgres to accept connections (attempt %d/30): %v", attempt, err)
			time.Sleep(1 * time.Second)
		}
		if err != nil {
			log.Fatalf("Fatal: postgres did not become ready: %v", err)
		}

		log.Printf("Running database migrations from source '%s'...", migrationsPath)
		if err := db.RunMigrations(adminDBURL, migrationsPath); err != nil {
			log.Fatalf("Fatal: failed to run database migrations: %v", err)
		}
		log.Println("Database migrations applied successfully.")

		// Ensure roles have the secret passwords if provided
		if apiPass != "" {
			escaped := strings.ReplaceAll(apiPass, "'", "''")
			if _, err := adminDB.Exec(fmt.Sprintf("ALTER ROLE api_role WITH PASSWORD '%s'", escaped)); err != nil {
				log.Printf("Notice: altering api_role password: %v", err)
			}
		}
		if signerPass != "" {
			escaped := strings.ReplaceAll(signerPass, "'", "''")
			if _, err := adminDB.Exec(fmt.Sprintf("ALTER ROLE signer_role WITH PASSWORD '%s'", escaped)); err != nil {
				log.Printf("Notice: altering signer_role password: %v", err)
			}
		}

		// Seed initial bootstrap API keys into app.api_keys
		if clientAPIKey != "" {
			hash := auth.HashToken(clientAPIKey)
			_, err := adminDB.Exec(`
				INSERT INTO app.api_keys (name, role, key_hash)
				VALUES ($1, $2, $3)
				ON CONFLICT (key_hash) DO NOTHING
			`, "bootstrap-client", auth.RoleClient, hash)
			if err != nil {
				log.Printf("Warning: failed to seed bootstrap client key: %v", err)
			} else {
				log.Printf("Bootstrapped client API key into app.api_keys")
			}
		}
		if signerToken != "" {
			hash := auth.HashToken(signerToken)
			_, err := adminDB.Exec(`
				INSERT INTO app.api_keys (name, role, key_hash)
				VALUES ($1, $2, $3)
				ON CONFLICT (key_hash) DO NOTHING
			`, "bootstrap-signer", auth.RoleSigner, hash)
			if err != nil {
				log.Printf("Warning: failed to seed bootstrap signer token: %v", err)
			} else {
				log.Printf("Bootstrapped signer token into app.api_keys")
			}
		}
		adminDB.Close()
	} else {
		log.Println("ADMIN_DATABASE_URL not set; skipping automatic startup migrations.")
	}

	// 3. Initialize runtime database pool
	log.Printf("Connecting to database as runtime role...")
	var pool *sql.DB
	var err error
	for attempt := 1; attempt <= 15; attempt++ {
		pool, err = db.Open(runtimeDBURL, db.DefaultPoolConfig())
		if err == nil {
			break
		}
		log.Printf("Waiting for runtime database connection (attempt %d/15): %v", attempt, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("Fatal: failed to open runtime database pool: %v", err)
	}
	defer pool.Close()
	log.Println("Connected to runtime database successfully.")

	// 4. Initialize auth store & dual-port server
	keyStore := auth.NewDBKeyStore(pool)
	srvConfig := server.Config{
		PublicAddr:   publicAddr,
		InternalAddr: internalAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	srv := server.New(srvConfig, pool, keyStore)

	// 5. Start listeners
	if err := srv.Start(); err != nil {
		log.Fatalf("Fatal: failed to start dual-port servers: %v", err)
	}
	log.Printf("Public HTTP server listening on %s", srv.PublicAddr())
	log.Printf("Internal HTTP server listening on %s", srv.InternalAddr())

	// 6. Graceful shutdown on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %s, initiating graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	} else {
		log.Println("Servers shut down gracefully.")
	}
}
