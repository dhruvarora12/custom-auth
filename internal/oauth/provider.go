package oauth

import "context"

type UserInfo struct {
	ProviderUserID string
	Email          string
	Name           *string
	AvatarURL      *string
}

type Provider interface {
	AuthURL(state string) string
	ExchangeAndGetUser(ctx context.Context, code string) (*UserInfo, error)
}
