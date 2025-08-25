package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	cookie "github.com/zitadel/oidc/v3/pkg/http"
	oidclib "github.com/zitadel/oidc/v3/pkg/oidc"
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

type OIDCState struct {
	Token    string `json:"token"`
	Redirect string `json:"redirect"`
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

func (c OIDCClient) NewLoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parameter := r.URL.Query().Get("redirect")
		redirect, err := url.Parse(parameter)
		if err != nil || !filepath.IsAbs(redirect.Path) {
			redirect, _ = url.Parse(c.baseURL)
		}

		stateMap := OIDCState{
			Token:    uuid.New().String(),
			Redirect: redirect.Path,
		}

		state := func() string {
			stateJson, _ := json.Marshal(stateMap)
			return string(stateJson)
		}

		handler := rp.AuthURLHandler(state, c.client)
		handler(w, r)
	})
}

func (c OIDCClient) NewCallbackHandler() http.Handler {
	baseURL, _ := url.Parse(c.baseURL)

	callback := func(w http.ResponseWriter, r *http.Request, tokens *oidclib.Tokens[*oidclib.IDTokenClaims], state string, rp rp.RelyingParty, info *oidclib.UserInfo) {
		var groups []string
		if groupsAny, ok := info.Claims["groups"]; ok {
			if groupsCast, ok := groupsAny.([]string); ok {
				groups = groupsCast
			} else {
				groups = []string{}
			}
		}
		var roles []string
		if rolesAny, ok := info.Claims["roles"]; ok {
			if rolesCast, ok := rolesAny.([]string); ok {
				roles = rolesCast
			} else {
				roles = []string{}
			}
		}

		expires := time.Now().Add(c.sessionLength)
		claims := UserSessionClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    c.baseURL,
				Subject:   tokens.IDTokenClaims.Subject,
				ExpiresAt: jwt.NewNumericDate(expires),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			SessionID: tokens.IDTokenClaims.SessionID,

			Username:      info.PreferredUsername,
			Email:         info.Email,
			EmailVerified: bool(info.EmailVerified),

			Groups: groups,
			Roles:  roles,

			GivenName:  info.GivenName,
			FamilyName: info.FamilyName,
			Nickname:   info.Nickname,

			IDTokenRaw: tokens.IDToken,
		}

		if claims.Subject == "" {
			http.Error(w, "subject claim is missing in ID token", http.StatusInternalServerError)
			return
		} else if claims.ExpiresAt == nil {
			http.Error(w, "expires-at claim is calculated incorrectly", http.StatusInternalServerError)
			return
		} else if claims.SessionID == "" {
			http.Error(w, "session-id claim is missing in ID token", http.StatusInternalServerError)
			return
		} else if claims.Username == "" {
			http.Error(w, "username claim is missing in user-info token", http.StatusInternalServerError)
			return
		} else if claims.Email == "" || !claims.EmailVerified {
			http.Error(w, "email claim or email-verified claim is missing in user-info token", http.StatusInternalServerError)
			return
		} else if claims.IDTokenRaw == "" {
			http.Error(w, "ID token for logout is missing", http.StatusInternalServerError)
			return
		}

		tokenString, err := NewUserToken(&claims, c.secret)
		if err != nil {
			http.Error(w, "creating JWT session token failed", http.StatusInternalServerError)
			return
		}
		cookie := http.Cookie{
			Name:     c.client.OAuthConfig().ClientID + "-session",
			Value:    tokenString,
			Path:     baseURL.Path,
			Domain:   baseURL.Hostname(),
			Expires:  expires,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, &cookie)

		// state parameter passed to callback by CodeExchangeHandler and UserinfoCallback is already validated (not modified and matches with HTTP URL parameter)
		var stateMap *OIDCState
		var redirect string
		err = json.Unmarshal([]byte(state), stateMap)
		if err != nil || stateMap.Redirect == "" {
			redirect = baseURL.Path
		} else {
			redirect = stateMap.Redirect
		}

		http.Redirect(w, r, redirect, http.StatusFound)
	}

	return rp.CodeExchangeHandler(rp.UserinfoCallback(callback), c.client)
}
