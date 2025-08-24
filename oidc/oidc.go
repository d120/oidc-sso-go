package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
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

type OIDCClient struct {
	client        rp.RelyingParty
	sessionLength time.Duration
	secret        []byte

	baseURL     string
	loginURL    string
	callbackURL string
	logoutURL   string
}

func (c OIDCConfig) NewClient() (*OIDCClient, error) {
	if _, err := url.Parse(c.URL); err != nil {
		return nil, errors.New("URL is invalid")
	}

	baseURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, errors.New("base URL is invalid")
	}

	if _, err := url.Parse(c.LoginURL); err != nil {
		return nil, errors.New("login URL is invalid")
	}

	if _, err := url.Parse(c.CallbackURL); err != nil {
		return nil, errors.New("callback URL is invalid")
	}

	if _, err := url.Parse(c.LogoutURL); err != nil {
		return nil, errors.New("logout URL is invalid")
	}

	if c.ClientID == "" {
		return nil, errors.New("ClientID is empty")
	}

	if c.ClientSecret == "" && !c.UsePKCE {
		return nil, errors.New("ClientSecret is empty and PKCE is disabled")
	}

	if len(c.Secret) == 0 {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, errors.New("generating cryptographically random key failed")
		}
		c.Secret = secret
	} else if len(c.Secret) < 16 {
		return nil, errors.New("secret is shorter than 16 bytes")
	}

	if c.SessionLength == nil {
		sessionLength, _ := time.ParseDuration("4h")
		c.SessionLength = &sessionLength
	} else if *c.SessionLength <= 0 {
		return nil, errors.New("session length is not positive")
	}

	if !slices.Contains(c.Scopes, "openid") {
		c.Scopes = append(c.Scopes, "openid")
	}

	var client *http.Client
	if c.Client != nil {
		client = c.Client
	} else {
		client = &http.Client{
			Timeout: time.Minute,
		}
	}

	var cookieHandler *cookie.CookieHandler
	if c.CookieHandler != nil {
		cookieHandler = c.CookieHandler
	} else {
		cookieHandler = cookie.NewCookieHandler(c.Secret, c.Secret, cookie.WithDomain(baseURL.Hostname()), cookie.WithPath(baseURL.Path), cookie.WithSameSite(http.SameSiteLaxMode))
	}

	options := []rp.Option{
		rp.WithHTTPClient(client),
		rp.WithCookieHandler(cookieHandler),
		rp.WithSigningAlgsFromDiscovery(),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	if c.UsePKCE {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	if c.Logger != nil {
		options = append(options, rp.WithLogger(c.Logger))
	}

	oidcRP, err := rp.NewRelyingPartyOIDC(context.Background(), c.URL, c.ClientID, c.ClientSecret, c.CallbackURL, c.Scopes, options...)
	if err != nil {
		return nil, err
	}
	oidcClient := OIDCClient{
		client:        oidcRP,
		sessionLength: *c.SessionLength,
		secret:        c.Secret,
		baseURL:       c.BaseURL,
		loginURL:      c.LoginURL,
		callbackURL:   c.CallbackURL,
		logoutURL:     c.LogoutURL,
	}

	return &oidcClient, nil
}
