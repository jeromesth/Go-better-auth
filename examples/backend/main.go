// Package main is a minimal backend example showing how to integrate
// go-better-auth with a real PostgreSQL database.
//
// Run via docker compose:
//
//	cd examples && docker compose up
//
// Or locally (requires a running Postgres instance):
//
//	export DATABASE_URL="postgres://auth:auth@localhost:5432/authdb?sslmode=disable"
//	go run .
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/examples/backend/adapter/postgres"
)

func main() {
	ctx := context.Background()

	dbURL := envOr("DATABASE_URL", "postgres://auth:auth@localhost:5432/authdb?sslmode=disable")
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connecting to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("pinging database: %v", err)
	}
	log.Println("connected to postgres")

	pgAdapter := postgres.New(pool)

	baseURL := envOr("BASE_URL", "http://localhost:8080")
	secret := envOr("AUTH_SECRET", "dev-secret-change-in-production-min-32-chars!!")

	auth := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Go Better Auth Example",
		BaseURL:  baseURL,
		BasePath: "/api/auth",
		Secret:   secret,
		Database: &betterauth.DatabaseConfig{
			Adapter: pgAdapter,
		},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled: true,
		},
		// Disable CSRF for this example so curl/Postman work without the
		// Origin header.  In production, remove this or set TrustedOrigins.
		Advanced: &betterauth.AdvancedConfig{
			DisableCSRFCheck: true,
		},
	})

	mux := http.NewServeMux()

	// Mount all auth endpoints under /api/auth/
	mux.Handle("/api/auth/", auth.Handler())

	// Simple health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Root: list available auth endpoints
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"app": "go-better-auth example",
			"endpoints": []string{
				"POST /api/auth/sign-up/email",
				"POST /api/auth/sign-in/email",
				"POST /api/auth/sign-out",
				"GET  /api/auth/get-session",
				"GET  /api/auth/list-sessions",
				"POST /api/auth/change-password",
				"POST /api/auth/request-password-reset",
				"POST /api/auth/reset-password",
				"POST /api/auth/update-user",
				"POST /api/auth/delete-user",
			},
		})
	})

	port := envOr("PORT", "8080")
	addr := ":" + port
	log.Printf("server listening on %s", addr)
	log.Printf("auth base URL: %s/api/auth", baseURL)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
