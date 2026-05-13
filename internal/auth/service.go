package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"auth-service/internal/user"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailTaken         = errors.New("email already registered")
	ErrUserNotFound       = errors.New("user not found")
)

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

type LoginInput struct {
	Email    string
	Password string
}

type Service struct {
	users  *user.Repository
	tokens *TokenManager
}

func NewService(users *user.Repository, tokens *TokenManager) *Service {
	return &Service{users: users, tokens: tokens}
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (*user.User, *TokenPair, error) {
	existing, err := s.users.FindByEmail(ctx, in.Email)
	if err == nil && existing != nil {
		return nil, nil, ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	hashStr := string(hash)
	name := in.Name
	u, err := s.users.Create(ctx, in.Email, &hashStr, &name)
	if err != nil {
		return nil, nil, err
	}

	pair, err := s.tokens.Issue(ctx, u.ID, u.Email)
	if err != nil {
		return nil, nil, err
	}
	return u, pair, nil
}

func (s *Service) Login(ctx context.Context, in LoginInput) (*user.User, *TokenPair, error) {
	u, err := s.users.FindByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	if u.PasswordHash == nil {
		return nil, nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*u.PasswordHash), []byte(in.Password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	pair, err := s.tokens.Issue(ctx, u.ID, u.Email)
	if err != nil {
		return nil, nil, err
	}
	return u, pair, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	userID, err := s.tokens.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if err := s.tokens.RevokeRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}
	return s.tokens.Issue(ctx, u.ID, u.Email)
}

func (s *Service) Logout(ctx context.Context, accessToken, refreshToken string) error {
	if accessToken != "" {
		_ = s.tokens.BlacklistAccessToken(ctx, accessToken, s.tokens.AccessTokenTTL())
	}
	if refreshToken != "" {
		_ = s.tokens.RevokeRefreshToken(ctx, refreshToken)
	}
	return nil
}

func (s *Service) ForgotPassword(ctx context.Context, email string) (string, error) {
	token := randomHex(32)
	expiresAt := time.Now().Add(time.Hour)
	if err := s.users.SetPasswordResetToken(ctx, email, token, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.users.ResetPassword(ctx, token, string(hash))
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
