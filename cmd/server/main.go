package main

import (
	"context"
	"log"
	"net/http"

	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/middleware"
	"auth-service/internal/oauth"
	"auth-service/internal/store"
	"auth-service/internal/user"
	"auth-service/migrations"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config:", err)
	}

	db, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("postgres:", err)
	}
	defer db.Close()

	rdb, err := store.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatal("redis:", err)
	}
	defer rdb.Close()

	if err := store.RunMigrations(cfg.DatabaseURL, migrations.FS); err != nil {
		log.Fatal("migrations:", err)
	}

	userRepo := user.NewRepository(db)
	tokenMgr := auth.NewTokenManager(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, rdb)
	authSvc := auth.NewService(userRepo, tokenMgr)
	authHandler := auth.NewHandler(authSvc, tokenMgr, userRepo)

	providers := map[string]oauth.Provider{}
	if cfg.GoogleClientID != "" {
		providers["google"] = oauth.NewGoogle(
			cfg.GoogleClientID, cfg.GoogleClientSecret,
			cfg.OAuthRedirectBase+"/auth/google/callback",
		)
	}
	if cfg.MicrosoftClientID != "" {
		providers["microsoft"] = oauth.NewMicrosoft(
			cfg.MicrosoftClientID, cfg.MicrosoftClientSecret,
			cfg.OAuthRedirectBase+"/auth/microsoft/callback",
		)
	}
	if cfg.FacebookClientID != "" {
		providers["facebook"] = oauth.NewFacebook(
			cfg.FacebookClientID, cfg.FacebookClientSecret,
			cfg.OAuthRedirectBase+"/auth/facebook/callback",
		)
	}
	if cfg.AppleClientID != "" {
		apple, err := oauth.NewApple(
			cfg.AppleClientID, cfg.AppleTeamID, cfg.AppleKeyID,
			cfg.ApplePrivateKey,
			cfg.OAuthRedirectBase+"/auth/apple/callback",
		)
		if err != nil {
			log.Fatal("apple provider:", err)
		}
		providers["apple"] = apple
	}

	oauthHandler := oauth.NewHandler(providers, userRepo, tokenMgr, rdb)

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/auth", func(r chi.Router) {
		// Public routes with rate limiting
		r.Group(func(r chi.Router) {
			r.Use(middleware.RateLimit(rdb, 10, cfg.AccessTokenTTL))
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
			r.Post("/forgot-password", authHandler.ForgotPassword)
			r.Post("/reset-password", authHandler.ResetPassword)
			r.Post("/verify-email", authHandler.VerifyEmail)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(tokenMgr))
			r.Post("/logout", authHandler.Logout)
			r.Get("/me", authHandler.Me)
		})

		// OAuth routes (one per configured provider)
		for name := range providers {
			n := name
			r.Get("/"+n, oauthHandler.Redirect(n))
			if n == "apple" {
				r.Post("/"+n+"/callback", oauthHandler.Callback(n))
			} else {
				r.Get("/"+n+"/callback", oauthHandler.Callback(n))
			}
		}
	})

	log.Printf("auth service listening on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatal(err)
	}
}
