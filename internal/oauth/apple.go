package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AppleProvider struct {
	clientID    string
	teamID      string
	keyID       string
	privateKey  *ecdsa.PrivateKey
	redirectURL string
}

func NewApple(clientID, teamID, keyID, privateKeyBase64, redirectURL string) (*AppleProvider, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode apple private key: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in apple private key")
	}

	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse apple private key: %w", err)
	}

	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apple private key must be ECDSA")
	}

	return &AppleProvider{
		clientID:    clientID,
		teamID:      teamID,
		keyID:       keyID,
		privateKey:  ecKey,
		redirectURL: redirectURL,
	}, nil
}

func (p *AppleProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"response_type": {"code"},
		"scope":         {"name email"},
		"response_mode": {"form_post"},
		"state":         {state},
	}
	return "https://appleid.apple.com/auth/authorize?" + params.Encode()
}

func (p *AppleProvider) clientSecret() (string, error) {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": p.teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": p.clientID,
	})
	tok.Header["kid"] = p.keyID
	return tok.SignedString(p.privateKey)
}

func (p *AppleProvider) ExchangeAndGetUser(ctx context.Context, code string) (*UserInfo, error) {
	secret, err := p.clientSecret()
	if err != nil {
		return nil, err
	}

	resp, err := http.PostForm("https://appleid.apple.com/auth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.clientID},
		"client_secret": {secret},
		"redirect_uri":  {p.redirectURL},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokenResp struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("apple token error: %s", tokenResp.Error)
	}

	// ParseUnverified is acceptable here because we just received this token directly
	// from Apple's token endpoint over TLS — it was not user-supplied.
	parsed, _, err := new(jwt.Parser).ParseUnverified(tokenResp.IDToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse apple id_token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid apple id_token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	return &UserInfo{ProviderUserID: sub, Email: email}, nil
}
