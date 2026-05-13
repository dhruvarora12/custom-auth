package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type MicrosoftProvider struct {
	config *oauth2.Config
}

func NewMicrosoft(clientID, clientSecret, redirectURL string) *MicrosoftProvider {
	return &MicrosoftProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile", "User.Read"},
			Endpoint:     microsoft.AzureADEndpoint("common"),
		},
	}
}

func (p *MicrosoftProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *MicrosoftProvider) ExchangeAndGetUser(ctx context.Context, code string) (*UserInfo, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("microsoft token exchange: %w", err)
	}

	resp, err := p.config.Client(ctx, token).Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var raw struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	email := raw.Mail
	if email == "" {
		email = raw.UserPrincipalName
	}

	info := &UserInfo{ProviderUserID: raw.ID, Email: email}
	if raw.DisplayName != "" {
		info.Name = &raw.DisplayName
	}
	return info, nil
}
