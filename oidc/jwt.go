package oidc

import (
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type UserSessionClaims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`

	Username      string `json:"preferred_username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	Groups []string `json:"groups"`
	Roles  []string `json:"roles"`

	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Nickname   string `json:"nickname"`
}

func NewUserToken(userSessionClaims *UserSessionClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userSessionClaims)
	return token.SignedString(secret)
}

func ValidateUserToken(tokenString string, secret []byte) (*UserSessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserSessionClaims{}, func(token *jwt.Token) (any, error) { return secret, nil }, jwt.WithExpirationRequired(), jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserSessionClaims); ok {
		return claims, nil
	}

	return nil, errors.New("claim structure is invalid")
}
