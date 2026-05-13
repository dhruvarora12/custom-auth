package user

import "time"

type User struct {
	ID                     string     `json:"id"`
	Email                  string     `json:"email"`
	PasswordHash           *string    `json:"-"`
	Name                   *string    `json:"name"`
	AvatarURL              *string    `json:"avatar_url"`
	EmailVerified          bool       `json:"email_verified"`
	EmailVerificationToken *string    `json:"-"`
	PasswordResetToken     *string    `json:"-"`
	PasswordResetExpiresAt *time.Time `json:"-"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}
