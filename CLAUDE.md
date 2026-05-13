# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A self-contained JWT authentication microservice in Go. Designed to be dropped into any project as a sidecar or standalone service. Supports email/password auth plus OAuth2 (Google, Microsoft, Facebook, Apple).

## Tech Stack

- **Language:** Go
- **HTTP Router:** Chi
- **Database:** PostgreSQL (via sqlc for type-safe query generation)
- **Cache:** Redis (refresh token storage, token blacklist, rate limiting, OAuth state)
- **Auth:** `golang-jwt/jwt` for JWT, `golang.org/x/oauth2` for OAuth2/OIDC

## Common Commands

```bash
# Run the service
go run ./cmd/server

# Build binary
go build -o bin/auth-service ./cmd/server

# Run all tests
go test ./...

# Run a single test
go test ./internal/auth/... -run TestTokenRefresh

# Generate sqlc code from SQL queries (after editing queries or schema)
sqlc generate

# Lint
golangci-lint run

# Run with hot reload (requires air)
air

# Apply DB migrations
goose -dir migrations postgres "$DATABASE_URL" up

# Roll back last migration
goose -dir migrations postgres "$DATABASE_URL" down
```

## Architecture

```
cmd/server/          → main.go, wires up router, DB, Redis, starts HTTP server
internal/
  auth/              → JWT issue/verify/refresh logic, token blacklist via Redis
  oauth/             → OAuth2 handlers for Google, Microsoft, Facebook, Apple
  user/              → User model, DB queries (sqlc-generated in user/db/)
  middleware/        → JWT auth middleware, rate limiter
  config/            → Env var loading (no config files, 12-factor)
migrations/          → SQL migration files (goose format)
queries/             → Raw SQL files that sqlc reads to generate Go code
sqlc.yaml            → sqlc configuration
```

## Key Design Decisions

- **sqlc over GORM:** SQL queries live in `queries/`, sqlc generates type-safe Go structs. Edit the `.sql` file, run `sqlc generate`, never touch the generated files in `*/db/`.
- **Redis for token state:** Refresh tokens are stored as hashed values in Redis with TTL. Access token blacklist on logout. Rate limiting keys are per-IP and per-user.
- **Apple callback is POST:** Unlike other providers, Apple sends the OAuth callback as a POST request with form data. The Apple callback route must accept POST.
- **Stateless access tokens:** Access tokens are short-lived (15min). Refresh tokens are long-lived (7d) and stored in Redis — revocation works by deleting the Redis key.
- **No sessions:** Purely token-based. The `/auth/me` endpoint validates the access token and returns the user from DB.

## Environment Variables

```
DATABASE_URL         postgres://user:pass@host:5432/dbname
REDIS_URL            redis://localhost:6379
JWT_SECRET           (min 32 chars)
JWT_ACCESS_TTL       15m
JWT_REFRESH_TTL      168h
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
MICROSOFT_CLIENT_ID
MICROSOFT_CLIENT_SECRET
FACEBOOK_CLIENT_ID
FACEBOOK_CLIENT_SECRET
APPLE_CLIENT_ID
APPLE_TEAM_ID
APPLE_KEY_ID
APPLE_PRIVATE_KEY    (base64-encoded .p8 key contents)
OAUTH_REDIRECT_BASE  https://yourdomain.com  (base URL for /auth/{provider}/callback)
PORT                 8080
```

## API Surface

```
POST /auth/register
POST /auth/login
POST /auth/logout              (requires access token)
POST /auth/refresh             (body: { refresh_token })
GET  /auth/me                  (requires access token)

GET  /auth/google
GET  /auth/google/callback
GET  /auth/microsoft
GET  /auth/microsoft/callback
GET  /auth/facebook
GET  /auth/facebook/callback
GET  /auth/apple
POST /auth/apple/callback      (Apple uses POST)

POST /auth/verify-email
POST /auth/forgot-password
POST /auth/reset-password
```
