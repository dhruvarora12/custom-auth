package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port string

	DatabaseURL string
	RedisURL    string

	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	GoogleClientID     string
	GoogleClientSecret string

	MicrosoftClientID     string
	MicrosoftClientSecret string

	FacebookClientID     string
	FacebookClientSecret string

	AppleClientID   string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string

	OAuthRedirectBase string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		accessTTL = 15 * time.Minute
	}
	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "168h"))
	if err != nil {
		refreshTTL = 7 * 24 * time.Hour
	}

	return &Config{
		Port:            getEnv("PORT", "8080"),
		DatabaseURL:     mustEnv("DATABASE_URL"),
		RedisURL:        getEnv("REDIS_URL", "redis://localhost:6379"),
		JWTSecret:       mustEnv("JWT_SECRET"),
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),

		MicrosoftClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
		MicrosoftClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),

		FacebookClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
		FacebookClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),

		AppleClientID:   os.Getenv("APPLE_CLIENT_ID"),
		AppleTeamID:     os.Getenv("APPLE_TEAM_ID"),
		AppleKeyID:      os.Getenv("APPLE_KEY_ID"),
		ApplePrivateKey: os.Getenv("APPLE_PRIVATE_KEY"),

		OAuthRedirectBase: getEnv("OAUTH_REDIRECT_BASE", "http://localhost:8080"),
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required env var missing: " + key)
	}
	return v
}
