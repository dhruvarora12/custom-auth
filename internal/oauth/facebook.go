package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type FacebookProvider struct {
	config *oauth2.Config
}

func NewFacebook(clientID, clientSecret, redirectURL string) *FacebookProvider {
	return &FacebookProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"email", "public_profile"},
			Endpoint:     facebook.Endpoint,
		},
	}
}

func (p *FacebookProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *FacebookProvider) ExchangeAndGetUser(ctx context.Context, code string) (*UserInfo, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("facebook token exchange: %w", err)
	}

	resp, err := p.config.Client(ctx, token).Get("https://graph.facebook.com/me?fields=id,name,email,picture.type(large)")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var raw struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct{ URL string `json:"url"` } `json:"data"`
		} `json:"picture"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	info := &UserInfo{ProviderUserID: raw.ID, Email: raw.Email}
	if raw.Name != "" {
		info.Name = &raw.Name
	}
	if raw.Picture.Data.URL != "" {
		info.AvatarURL = &raw.Picture.Data.URL
	}
	return info, nil
}
