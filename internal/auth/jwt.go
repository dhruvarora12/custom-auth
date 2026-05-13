package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
}

type TokenManager struct {
	secret          []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	rdb             *redis.Client
}

func NewTokenManager(secret string, accessTTL, refreshTTL time.Duration, rdb *redis.Client) *TokenManager {
	return &TokenManager{
		secret:          []byte(secret),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		rdb:             rdb,
	}
}

func (tm *TokenManager) Issue(ctx context.Context, userID, email string) (*TokenPair, error) {
	now := time.Now()
	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.accessTokenTTL)),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(tm.secret)
	if err != nil {
		return nil, err
	}

	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(rawBytes)

	if err := tm.rdb.Set(ctx, "refresh:"+hashToken(refreshToken), userID, tm.refreshTokenTTL).Err(); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(tm.accessTokenTTL.Seconds()),
	}, nil
}

func (tm *TokenManager) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tm.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (tm *TokenManager) ValidateRefreshToken(ctx context.Context, token string) (string, error) {
	userID, err := tm.rdb.Get(ctx, "refresh:"+hashToken(token)).Result()
	if err != nil {
		return "", fmt.Errorf("invalid or expired refresh token")
	}
	return userID, nil
}

func (tm *TokenManager) RevokeRefreshToken(ctx context.Context, token string) error {
	return tm.rdb.Del(ctx, "refresh:"+hashToken(token)).Err()
}

func (tm *TokenManager) BlacklistAccessToken(ctx context.Context, tokenStr string, ttl time.Duration) error {
	return tm.rdb.Set(ctx, "blacklist:"+tokenStr, "1", ttl).Err()
}

func (tm *TokenManager) IsBlacklisted(ctx context.Context, tokenStr string) bool {
	return tm.rdb.Exists(ctx, "blacklist:"+tokenStr).Val() == 1
}

func (tm *TokenManager) AccessTokenTTL() time.Duration {
	return tm.accessTokenTTL
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
