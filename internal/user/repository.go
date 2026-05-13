package user

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, email string, passwordHash *string, name *string) (*User, error) {
	u := &User{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, name)
		VALUES ($1, $2, $3)
		RETURNING id, email, password_hash, name, avatar_url, email_verified, created_at, updated_at
	`, email, passwordHash, name).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL,
		&u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	return u, err
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, name, avatar_url, email_verified,
		       email_verification_token, password_reset_token, password_reset_expires_at,
		       created_at, updated_at
		FROM users WHERE email = $1
	`, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL,
		&u.EmailVerified, &u.EmailVerificationToken, &u.PasswordResetToken,
		&u.PasswordResetExpiresAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, name, avatar_url, email_verified, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL,
		&u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) FindOrCreateByOAuth(ctx context.Context, provider, providerUserID, email string, name, avatarURL *string) (*User, error) {
	var userID string
	err := r.db.QueryRow(ctx,
		`SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&userID)

	if err == nil {
		return r.FindByID(ctx, userID)
	}

	// Link to existing email-registered user if present
	existing, err := r.FindByEmail(ctx, email)
	if err == nil {
		_, err = r.db.Exec(ctx, `
			INSERT INTO oauth_accounts (user_id, provider, provider_user_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (provider, provider_user_id) DO NOTHING
		`, existing.ID, provider, providerUserID)
		return existing, err
	}

	// Create brand-new user + OAuth account in a transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	u := &User{}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, name, avatar_url, email_verified)
		VALUES ($1, $2, $3, true)
		RETURNING id, email, password_hash, name, avatar_url, email_verified, created_at, updated_at
	`, email, name, avatarURL).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL,
		&u.EmailVerified, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO oauth_accounts (user_id, provider, provider_user_id) VALUES ($1, $2, $3)`,
		u.ID, provider, providerUserID,
	)
	if err != nil {
		return nil, err
	}

	return u, tx.Commit(ctx)
}

func (r *Repository) VerifyEmail(ctx context.Context, token string) (*User, error) {
	u := &User{}
	err := r.db.QueryRow(ctx, `
		UPDATE users
		SET email_verified = true, email_verification_token = NULL, updated_at = NOW()
		WHERE email_verification_token = $1
		RETURNING id, email, name, avatar_url, email_verified, created_at, updated_at
	`, token).Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *Repository) SetPasswordResetToken(ctx context.Context, email, token string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = NOW()
		WHERE email = $3
	`, token, expiresAt, email)
	return err
}

func (r *Repository) ResetPassword(ctx context.Context, token, newHash string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE users
		SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL, updated_at = NOW()
		WHERE password_reset_token = $2 AND password_reset_expires_at > NOW()
	`, newHash, token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
