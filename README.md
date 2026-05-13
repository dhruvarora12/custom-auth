# custom-auth

A self-contained JWT authentication microservice built in Go. Drop it into any project as a sidecar or standalone service — no auth logic needed in the host app.

## Features

- **Email/password auth** — register, login, logout, refresh
- **OAuth2 social login** — Google, Microsoft, Facebook, Apple
- **Rotating refresh tokens** — stored hashed in Redis, revoked on logout
- **Access token blacklist** — instant invalidation on logout via Redis
- **Rate limiting** — per-IP, per-route, Redis-backed
- **Auto migrations** — schema applied on startup via embedded SQL
- **~15MB Docker image** — distroless base, single binary

## Stack

| Layer | Choice |
|---|---|
| Language | Go |
| Router | [Chi](https://github.com/go-chi/chi) |
| Database | PostgreSQL (pgx, no ORM) |
| Cache | Redis |
| Migrations | [Goose](https://github.com/pressly/goose) (embedded, auto-run) |
| JWT | [golang-jwt/jwt v5](https://github.com/golang-jwt/jwt) |
| OAuth2 | [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) |

## API

```
POST   /auth/register
POST   /auth/login
POST   /auth/logout            — requires Bearer token
POST   /auth/refresh
GET    /auth/me                — requires Bearer token

POST   /auth/verify-email
POST   /auth/forgot-password
POST   /auth/reset-password

GET    /auth/google
GET    /auth/google/callback
GET    /auth/microsoft
GET    /auth/microsoft/callback
GET    /auth/facebook
GET    /auth/facebook/callback
GET    /auth/apple
POST   /auth/apple/callback    — Apple uses POST

GET    /health
```

### Request / Response examples

**Register**
```http
POST /auth/register
Content-Type: application/json

{ "email": "user@example.com", "password": "secret", "name": "Jane" }
```
```json
{
  "user": { "id": "...", "email": "user@example.com", "name": "Jane", ... },
  "tokens": { "access_token": "...", "refresh_token": "...", "expires_in": 900 }
}
```

**Refresh**
```http
POST /auth/refresh
Content-Type: application/json

{ "refresh_token": "..." }
```

**Protected route**
```http
GET /auth/me
Authorization: Bearer <access_token>
```

**Logout** (invalidates both tokens immediately)
```http
POST /auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{ "refresh_token": "..." }
```

## Getting started

### With Docker (recommended)

```bash
cp .env.example .env
# fill in .env — at minimum set JWT_SECRET
docker compose up --build
```

Service is available at `http://localhost:8080`.

### Local development

**Prerequisites:** Go 1.21+, PostgreSQL 14+, Redis 7+

```bash
cp .env.example .env
# edit .env with your local DB/Redis URLs

go run ./cmd/server
```

### Build binary

```bash
go build -o bin/auth-service ./cmd/server
./bin/auth-service
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | PostgreSQL connection string |
| `REDIS_URL` | no | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | yes | — | Min 32 chars, used to sign access tokens |
| `JWT_ACCESS_TTL` | no | `15m` | Access token lifetime |
| `JWT_REFRESH_TTL` | no | `168h` | Refresh token lifetime (7 days) |
| `PORT` | no | `8080` | HTTP listen port |
| `OAUTH_REDIRECT_BASE` | no | `http://localhost:8080` | Base URL for OAuth callbacks |
| `GOOGLE_CLIENT_ID` | no | — | Leave empty to disable Google login |
| `GOOGLE_CLIENT_SECRET` | no | — | |
| `MICROSOFT_CLIENT_ID` | no | — | Leave empty to disable Microsoft login |
| `MICROSOFT_CLIENT_SECRET` | no | — | |
| `FACEBOOK_CLIENT_ID` | no | — | Leave empty to disable Facebook login |
| `FACEBOOK_CLIENT_SECRET` | no | — | |
| `APPLE_CLIENT_ID` | no | — | Leave empty to disable Apple login |
| `APPLE_TEAM_ID` | no | — | |
| `APPLE_KEY_ID` | no | — | |
| `APPLE_PRIVATE_KEY` | no | — | Base64-encoded `.p8` file contents |

OAuth providers are opt-in — any provider with empty credentials is silently skipped.

## OAuth setup

### Google
1. Go to [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials
2. Create an OAuth 2.0 Client ID (Web application)
3. Add `{OAUTH_REDIRECT_BASE}/auth/google/callback` as an authorized redirect URI

### Microsoft
1. Go to [portal.azure.com](https://portal.azure.com) → Azure Active Directory → App registrations
2. Register a new app, add a Web redirect URI: `{OAUTH_REDIRECT_BASE}/auth/microsoft/callback`
3. Under Certificates & secrets, create a new client secret

### Facebook
1. Go to [developers.facebook.com](https://developers.facebook.com) → My Apps → Create App
2. Add the Facebook Login product
3. Add `{OAUTH_REDIRECT_BASE}/auth/facebook/callback` as a valid OAuth redirect URI

### Apple
1. Go to [developer.apple.com](https://developer.apple.com) → Certificates, IDs & Profiles → Keys
2. Create a new key with Sign In with Apple enabled, download the `.p8` file
3. Register a Services ID (this is your `APPLE_CLIENT_ID`) and add `{OAUTH_REDIRECT_BASE}/auth/apple/callback` as a return URL
4. Base64-encode the `.p8` file: `base64 -i AuthKey_XXXXXX.p8`

## Project structure

```
cmd/server/          — main.go, wires everything up
internal/
  config/            — env loading
  store/             — postgres pool, redis client, migration runner
  user/              — User model + repository (raw pgx queries)
  auth/              — JWT manager, auth service, HTTP handlers
  oauth/             — one file per provider + shared callback handler
  middleware/        — JWT guard, Redis rate limiter
migrations/          — SQL files (goose format) + embed.go
```

## Token design

- **Access token** — signed JWT (HS256), 15 min TTL. Contains `sub` (user ID) and `email`.
- **Refresh token** — random 32-byte hex string, stored as SHA-256 hash in Redis with TTL.
- **Logout** — access token is added to a Redis blacklist for its remaining TTL; refresh token is deleted.
- **Refresh rotation** — old refresh token is revoked and a new pair is issued atomically.

## License

MIT
