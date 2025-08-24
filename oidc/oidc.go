package oidc

import (
	"log/slog"
	"net/http"
	"time"

	cookie "github.com/zitadel/oidc/v3/pkg/http"
)

type OIDCConfig struct {
	// OIDC configuration options
	URL          string
	ClientID     string
	ClientSecret string
	UsePKCE      bool
	Scopes       []string

	// additional options
	SessionLength *time.Duration
	Secret        []byte
	Client        *http.Client
	CookieHandler *cookie.CookieHandler
	Logger        *slog.Logger

	// top-most application URL (used for cookie scopes and redirects)
	BaseURL string

	// handler URLs
	LoginURL    string
	CallbackURL string
	LogoutURL   string
}
