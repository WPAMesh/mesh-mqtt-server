package models

import (
	"time"

	"golang.org/x/oauth2"
)

type OAuthToken struct {
	UserID       int        `db:"user_id"`
	TokenType    *string    `db:"token_type"`
	AccessToken  *string    `db:"access_token"`
	RefreshToken *string    `db:"refresh_token"`
	Expiration   *time.Time `db:"expiration"`
}

func (t *OAuthToken) UpdateFromOAuth2(token oauth2.Token) {
	t.TokenType = &token.TokenType
	t.AccessToken = &token.AccessToken
	if token.RefreshToken != "" {
		t.RefreshToken = &token.RefreshToken
	}
	t.Expiration = &token.Expiry
}

func (t *OAuthToken) ToOAuth2() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  *t.AccessToken,
		RefreshToken: *t.RefreshToken,
		Expiry:       *t.Expiration,
		TokenType:    *t.TokenType,
	}
}
