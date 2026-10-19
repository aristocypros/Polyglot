package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"polyglot/api/internal/auth"
	"polyglot/api/internal/handlers"
	"polyglot/api/internal/problem"
)

// Config defines the configuration for the dual-port HTTP server.
type Config struct {
	PublicAddr   string        // Listen address for public server (default: ":8080")
	InternalAddr string        // Listen address for internal server (default: ":8081")
	ReadTimeout  time.Duration // Server read timeout
	WriteTimeout time.Duration // Server write timeout
	IdleTimeout  time.Duration // Server idle timeout
}

// DefaultConfig returns default configuration values.
func DefaultConfig() Config {
	return Config{
		PublicAddr:   ":8080",
		InternalAddr: ":8081",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Server coordinates the dual HTTP servers (public and internal listeners).
type Server struct {
	cfg            Config
	db             *sql.DB
	keyStore       auth.KeyStore
	signerRegistry *handlers.SignerRegistry
	handlers       *handlers.Handler
	publicMux      *http.ServeMux
	internalMux    *http.ServeMux
	publicServer   *http.Server
	internalServer *http.Server

	mu        sync.Mutex
	pubLn     net.Listener
	intLn     net.Listener
	isRunning bool
}

// New creates a new dual-port Server instance.
func New(cfg Config, db *sql.DB, keyStore auth.KeyStore) *Server {
	if cfg.PublicAddr == "" {
		cfg.PublicAddr = ":8080"
	}
	if cfg.InternalAddr == "" {
		cfg.InternalAddr = ":8081"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}

	publicMux := http.NewServeMux()
	internalMux := http.NewServeMux()
	signerReg := handlers.NewSignerRegistry(nil)
	h := handlers.New(db, signerReg)

	s := &Server{
		cfg:            cfg,
		db:             db,
		keyStore:       keyStore,
		signerRegistry: signerReg,
		handlers:       h,
		publicMux:      publicMux,
		internalMux:    internalMux,
	}

	s.setupDefaultRoutes()

	s.publicServer = &http.Server{
		Addr:         cfg.PublicAddr,
		Handler:      publicMux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	s.internalServer = &http.Server{
		Addr:         cfg.InternalAddr,
		Handler:      internalMux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return s
}

// setupDefaultRoutes wires up the base foundation routes and auth middlewares.
func (s *Server) setupDefaultRoutes() {
	// 1. Public /healthz: no auth, liveness check
	s.publicMux.HandleFunc("GET /healthz", s.handlers.Healthz)

	if s.keyStore != nil {
		authenticate := auth.Authenticate(s.keyStore)

		// 2. /v1/signer: accepts any valid authenticated role (client or signer) or unauthenticated
		signerHandler := auth.AuthenticateOptional(s.keyStore, auth.RoleClient, auth.RoleSigner)(http.HandlerFunc(s.handlers.GetSigner))
		s.publicMux.Handle("/v1/signer", signerHandler)

		// 3. /v1/requests: requires client role
		clientRequestsHandler := authenticate(auth.RequireRole(auth.RoleClient)(http.HandlerFunc(s.handlers.HandleRequests)))
		s.publicMux.Handle("/v1/requests", clientRequestsHandler)
		s.publicMux.Handle("/v1/requests/", clientRequestsHandler)

		// 4. /v1/wallets: requires client role
		clientWalletsHandler := authenticate(auth.RequireRole(auth.RoleClient)(http.HandlerFunc(s.handlers.HandleWallets)))
		s.publicMux.Handle("/v1/wallets", clientWalletsHandler)
		s.publicMux.Handle("/v1/wallets/", clientWalletsHandler)

		// 5. /internal/*: requires signer role on internal listener (:8081)
		claimHandler := authenticate(auth.RequireRole(auth.RoleSigner)(http.HandlerFunc(s.handlers.HandleInternalClaim)))
		s.internalMux.Handle("/internal/claim", claimHandler)

		resultsHandler := authenticate(auth.RequireRole(auth.RoleSigner)(http.HandlerFunc(s.handlers.HandleInternalResults)))
		s.internalMux.Handle("/internal/results", resultsHandler)

		fallbackHandler := authenticate(auth.RequireRole(auth.RoleSigner)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = problem.Write(w, http.StatusNotFound, problem.CodeInvalidRequest, "Not Found", "internal route not found")
		})))
		s.internalMux.Handle("/internal/", fallbackHandler)
	}
}

// Handlers returns the public Handler instance.
func (s *Server) Handlers() *handlers.Handler {
	return s.handlers
}

// SignerRegistry returns the attached SignerRegistry.
func (s *Server) SignerRegistry() *handlers.SignerRegistry {
	return s.signerRegistry
}

// PublicMux returns the public HTTP ServeMux for adding additional route handlers.
func (s *Server) PublicMux() *http.ServeMux {
	return s.publicMux
}

// InternalMux returns the internal HTTP ServeMux for adding internal route handlers.
func (s *Server) InternalMux() *http.ServeMux {
	return s.internalMux
}

// PublicHandler returns the http.Handler serving public routes.
func (s *Server) PublicHandler() http.Handler {
	return s.publicMux
}

// InternalHandler returns the http.Handler serving internal routes.
func (s *Server) InternalHandler() http.Handler {
	return s.internalMux
}

// Start binds listeners and starts both public and internal HTTP servers in background goroutines.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return errors.New("server is already running")
	}

	pubLn, err := net.Listen("tcp", s.cfg.PublicAddr)
	if err != nil {
		return fmt.Errorf("failed to bind public listener on %s: %w", s.cfg.PublicAddr, err)
	}

	intLn, err := net.Listen("tcp", s.cfg.InternalAddr)
	if err != nil {
		_ = pubLn.Close()
		return fmt.Errorf("failed to bind internal listener on %s: %w", s.cfg.InternalAddr, err)
	}

	s.pubLn = pubLn
	s.intLn = intLn
	s.isRunning = true

	go func() {
		if err := s.publicServer.Serve(pubLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error if needed
		}
	}()

	go func() {
		if err := s.internalServer.Serve(intLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error if needed
		}
	}()

	return nil
}

// Shutdown gracefully stops both public and internal servers within the provided context timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return nil
	}
	s.isRunning = false
	s.mu.Unlock()

	var wg sync.WaitGroup
	var pubErr, intErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		pubErr = s.publicServer.Shutdown(ctx)
	}()
	go func() {
		defer wg.Done()
		intErr = s.internalServer.Shutdown(ctx)
	}()

	wg.Wait()

	if pubErr != nil && intErr != nil {
		return fmt.Errorf("public server shutdown error: %v; internal server shutdown error: %v", pubErr, intErr)
	}
	if pubErr != nil {
		return fmt.Errorf("public server shutdown error: %w", pubErr)
	}
	if intErr != nil {
		return fmt.Errorf("internal server shutdown error: %w", intErr)
	}

	return nil
}

// PublicAddr returns the actual bound address of the public listener.
func (s *Server) PublicAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pubLn != nil {
		return s.pubLn.Addr().String()
	}
	return s.cfg.PublicAddr
}

// InternalAddr returns the actual bound address of the internal listener.
func (s *Server) InternalAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.intLn != nil {
		return s.intLn.Addr().String()
	}
	return s.cfg.InternalAddr
}
