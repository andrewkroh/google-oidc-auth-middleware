// Licensed to Andrew Kroh under one or more agreements.
// Andrew Kroh licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package google_oidc_auth_middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// https://accounts.google.com/.well-known/openid-configuration
const (
	authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint         = "https://oauth2.googleapis.com/token"
)

var (
	errExpiredCookie             = errors.New("cookie is expired")
	errInvalidCookieSignature    = errors.New("invalid cookie signature")
	errConfigMissingCookieSecret = errors.New("cookie.secret must be configured")
	errConfigMissingAuthorized   = errors.New("authorized.emails and/or authorized.domains must be configured")
	errEmailNotVerified          = errors.New("email address is not verified by OIDC provider")
	errEmailClaimMissing         = errors.New("email address claim missing from OIDC id_token")
)

// Config the plugin configuration.
type Config struct {
	OIDC       OIDCConfig
	Cookie     CookieConfig
	Authorized AuthorizedConfig
	Debug      bool // Enable debug logging to stdout.
}

type CookieConfig struct {
	Name     string // Name of the cookie. It can be customized to avoid collisions when running multiple instances of the middleware.
	Path     string // You can use this to limit the scope of the cookie to a specific path. Defaults to '/'.
	Secret   string // Secret is the HMAC key and helps provide integrity protection for cookies.
	Duration string // Validity period for new cookies. Users are granted access for this length of time regardless of changes to user's account in the OIDC provider.
	Insecure bool   // Only set this if you are using HTTP.
	SameSite string // SameSite attribute for cookies. Options: "Strict", "Lax", "None". Defaults to "Lax".

	duration time.Duration   // Parsed Duration value.
	sameSite http.SameSite   // Parsed SameSite value.
}

type AuthorizedConfig struct {
	Emails  []string // List of allowed email addresses.
	Domains []string // List of allowed domains.
}

type OIDCConfig struct {
	// The OAuth Client ID from the provider for OIDC roles.
	ClientID string

	// The OAuth Client Secret from the provider for OIDC roles.
	ClientSecret string

	// The path where the OIDC provider will redirect user after authenticating.
	CallbackPath string

	// Prompt is an optional, space-delimited, case-sensitive list of prompts to
	// present the user. If you don't specify this parameter, the user will be
	// prompted only the first time your project requests access.
	// Possible values are: 'none', 'consent', 'select_account'.
	Prompt string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		OIDC: OIDCConfig{
			CallbackPath: "/oidc/callback",
		},
		Cookie: CookieConfig{
			Name:     "oidc_auth",
			Path:     "/",
			Duration: "24h",
			SameSite: "Lax",
		},
	}
}

// New created a new Google OIDC auth middleware plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var err error
	if config.Cookie.duration, err = time.ParseDuration(config.Cookie.Duration); err != nil {
		return nil, fmt.Errorf("invalid cookie duration: %w", err)
	}
	if config.Cookie.Secret == "" {
		return nil, errConfigMissingCookieSecret
	}
	if len(config.Authorized.Emails) == 0 && len(config.Authorized.Domains) == 0 {
		return nil, errConfigMissingAuthorized
	}

	// Parse and validate SameSite attribute.
	switch strings.ToLower(config.Cookie.SameSite) {
	case "strict":
		config.Cookie.sameSite = http.SameSiteStrictMode
	case "lax", "":
		config.Cookie.sameSite = http.SameSiteLaxMode
	case "none":
		config.Cookie.sameSite = http.SameSiteNoneMode
	default:
		return nil, fmt.Errorf("invalid cookie.sameSite value %q: must be Strict, Lax, or None", config.Cookie.SameSite)
	}

	// Logging is only enabled when debug=true.
	logDestination := io.Discard
	if config.Debug {
		logDestination = os.Stdout
	}
	debug := log.New(logDestination, "["+name+"] ", 0)

	cookieSigner := newCookieSigner(config.Cookie.Secret)

	authnHandler := &authnRedirectHandler{
		debug:                 debug,
		config:                config,
		signer:                cookieSigner,
		authorizationEndpoint: authorizationEndpoint,
	}

	authzHandler := &cookieAuthzHandler{
		debug:        debug,
		cookieName:   config.Cookie.Name,
		cookiePath:   config.Cookie.Path,
		cookieSigner: cookieSigner,
		allowEmails:  toMap(config.Authorized.Emails),
		allowDomains: toMap(config.Authorized.Domains),
		next:         next,
		authN:        authnHandler,
	}

	callbackHandler := &oidcCallbackHandler{
		debug:         debug,
		config:        config,
		tokenEndpoint: tokenEndpoint,
		signer:        cookieSigner,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == config.OIDC.CallbackPath {
			callbackHandler.ServeHTTP(w, r)
			return
		}
		authzHandler.ServeHTTP(w, r)
	}), nil
}

// ############################################
// cookieAuthzHandler
// ############################################

// cookieAuthzHandler checks if requests are authorized by the presence of an
// HMAC signed cookie containing the user's email address. The email address
// must be specified in an allowlist.
type cookieAuthzHandler struct {
	debug        *log.Logger         // Debug logger (enabled via config).
	cookieName   string              // Name of cookie to read.
	cookiePath   string              // Path of the cookie (for deletion purposes).
	cookieSigner *cookieSigner       // Encoder / decoder for signed cookies.
	allowEmails  map[string]struct{} // Allowed email addresses.
	allowDomains map[string]struct{} // Allowed domains.
	next         http.Handler        // Handler for authorized requests.
	authN        http.Handler        // Handler to authenticate the user.
}

func (h *cookieAuthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Is the request already authorized with a cookie?
	ac, loginHint, err := newAuthCookieFromRequest(r, h.cookieSigner, h.cookieName)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			h.debug.Printf("Invalid cookie in request from addr=%s: %v", r.RemoteAddr, err)
		}
		if loginHint != "" {
			r = r.WithContext(context.WithValue(r.Context(), "login_hint", loginHint))
		}
		goto AUTH
	}

	if isAuthorized(ac.Email, ac.Domain, h.allowEmails, h.allowDomains) {
		h.debug.Printf("Received authorized request from user=%s of domain=%s at addr=%s for path=%s",
			ac.Email, ac.Domain, r.RemoteAddr, r.URL.Path)
		r.Header.Set("X-Forwarded-User", ac.Email)
		h.next.ServeHTTP(w, r)
		return
	} else {
		h.debug.Printf("Request not authorized for user=%s of domain=%s at addr=%s for path=%s",
			ac.Email, ac.Domain, r.RemoteAddr, r.URL.Path)
		http.Error(w, ac.Email+" is not authorized", http.StatusUnauthorized)
		return
	}

AUTH:
	// Clear the cookie if it exists.
	deleteCookie(w, r, h.cookieName, h.cookiePath)

	// Authenticate.
	h.authN.ServeHTTP(w, r)
}

// ############################################
// authnRedirectHandler
// ############################################

// authnRedirectHandler redirects the user to the OIDC provider to for
// authentication.
type authnRedirectHandler struct {
	debug                 *log.Logger
	config                *Config
	signer                *cookieSigner
	authorizationEndpoint string
}

func (h *authnRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n, err := nonce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	originalURL := *r.URL
	originalURL.Scheme = r.Header.Get("X-Forwarded-Proto")
	originalURL.Host = r.Header.Get("X-Forwarded-Host")

	// Set a singed cookie that holds state and provides CSRF protection.
	expires := time.Now().Add(time.Hour)
	csrfCookieValue, err := newCSRFCookie(h.signer, expires, n, originalURL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName(h.config.Cookie.Name),
		Value:    csrfCookieValue,
		Path:     h.config.OIDC.CallbackPath,
		Expires:  expires,
		Secure:   !h.config.Cookie.Insecure,
		HttpOnly: true,
		SameSite: h.config.Cookie.sameSite,
	})

	u, _ := url.Parse(h.authorizationEndpoint)
	q := u.Query()
	q.Set("client_id", h.config.OIDC.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid email")
	q.Set("redirect_uri", redirectURI(r, h.config.OIDC.CallbackPath))
	q.Set("nonce", n)
	q.Set("state", n)
	if loginHint, ok := r.Context().Value("login_hint").(string); ok {
		q.Set("login_hint", loginHint)
	}
	if h.config.OIDC.Prompt != "" {
		q.Set("prompt", h.config.OIDC.Prompt)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

// ############################################
// oidcCallbackHandler
// ############################################

// oidcCallbackHandler handles callbacks from the OIDC provider that contain
// the auth code.
type oidcCallbackHandler struct {
	debug         *log.Logger
	config        *Config
	tokenEndpoint string // Provider token endpoint for exchanging token.
	signer        *cookieSigner
}

func (h *oidcCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		h.debug.Println("Missing 'state' query param in oidc callback.")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.debug.Println("Missing 'code' query param in oidc callback.")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	// Check CSRF cookie. There should be a cookie in the request whose nonce
	// matches the data in the state param.
	cookieName := csrfCookieName(h.config.Cookie.Name)
	csrfCookie, err := newCSRFCookieFromRequest(r, h.signer, cookieName)
	if err != nil {
		h.debug.Printf("Invalid CSRF cookie in OIDC callback for addr=%s: %v", r.RemoteAddr, err)
		deleteCookie(w, r, cookieName, h.config.OIDC.CallbackPath)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	if csrfCookie.Nonce != state {
		h.debug.Printf("OIDC callback state doesn't match CSRF cookie for addr=%s", r.RemoteAddr)
		deleteCookie(w, r, cookieName, h.config.OIDC.CallbackPath)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	deleteCookie(w, r, cookieName, h.config.OIDC.CallbackPath)

	token, err := h.exchangeToken(code, redirectURI(r, h.config.OIDC.CallbackPath))
	if err != nil {
		h.debug.Println("Failed exchanging auth code for token.", err)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	email, domain, err := parseJWT(token.IDToken)
	if err != nil {
		h.debug.Println("Failed parsing email claim from id_token", err)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	if err = h.setCookie(w, email, domain); err != nil {
		h.debug.Printf("failed to build signed cookie: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, csrfCookie.RedirectURL, http.StatusFound)
}

type oauthToken struct {
	// ID tokens are JSON Web Tokens (JWTs) that conform to the OpenID Connect (OIDC) specification.
	IDToken string `json:"id_token"`
}

// exchangeToken communicates with the OIDC provider's token endpoint to
// exchange the code for an id_token which will contain the user's identity.
func (h *oidcCallbackHandler) exchangeToken(code, redirectURI string) (*oauthToken, error) {
	resp, err := http.PostForm(h.tokenEndpoint,
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {h.config.OIDC.ClientID},
			"client_secret": {h.config.OIDC.ClientSecret},
			"code":          {code},
			"redirect_uri":  {redirectURI},
		})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failure response received from token endoint: status=%d, body=%s", resp.StatusCode, body)
	}

	var token *oauthToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed decoding token response: %w", err)
	}

	return token, nil
}

func (h *oidcCallbackHandler) setCookie(w http.ResponseWriter, email, domain string) error {
	expires := time.Now().Add(h.config.Cookie.duration)

	ac, err := newAuthCookie(h.signer, expires, email, domain)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:  h.config.Cookie.Name,
		Value: ac,
		Path:  h.config.Cookie.Path,
		// Remember the user's email for 120 days so that we can give a
		// login_hint to OIDC even after their authorization expires.
		Expires:  expires.Add(120 * 24 * time.Hour),
		Secure:   !h.config.Cookie.Insecure,
		HttpOnly: true,
		SameSite: h.config.Cookie.sameSite,
	})
	return nil
}

// ############################################
// authCookie
// ############################################

// AuthCookie represents the data stored in the requestor's cookie jar to
// authenticate future requests.
type AuthCookie struct {
	ExpiresUnixSec int64  `json:"exp"`
	Email          string `json:"email"`
	Domain         string `json:"domain,omitempty"`
}

func newAuthCookie(signer *cookieSigner, expires time.Time, email, domain string) (string, error) {
	c := &AuthCookie{
		ExpiresUnixSec: expires.Unix(),
		Email:          email,
		Domain:         domain,
	}
	value, err := signer.Encode(c)
	if err != nil {
		return "", fmt.Errorf("failed to encode auth cookie: %w", err)
	}
	return value, nil
}

func newAuthCookieFromRequest(r *http.Request, signer *cookieSigner, cookieName string) (c *AuthCookie, loginHint string, err error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, "", fmt.Errorf("cookie %s not found in request: %w", cookieName, err)
	}

	if err = signer.Decode(cookie.Value, &c); err != nil {
		return nil, "", err
	}

	if c.Expired() {
		return nil, c.Email, fmt.Errorf("cookie for user %q expired: %w", c.Email, errExpiredCookie)
	}

	return c, "", nil
}

func (c *AuthCookie) Expired() bool {
	return time.Now().After(time.Unix(c.ExpiresUnixSec, 0))
}

func (c *AuthCookie) Base64() string {
	j, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(j)
}

// ############################################
// csrfCookie
// ############################################

type CSRFCookie struct {
	ExpiresUnixSec int64  `json:"exp"`
	Nonce          string `json:"nonce"`
	RedirectURL    string `json:"url"` // URI to redirect the user after authenticating.
}

func newCSRFCookie(signer *cookieSigner, expires time.Time, nonce, url string) (string, error) {
	c := &CSRFCookie{
		ExpiresUnixSec: expires.Unix(),
		Nonce:          nonce,
		RedirectURL:    url,
	}
	value, err := signer.Encode(c)
	if err != nil {
		return "", fmt.Errorf("failed to encode csrf cookie: %w", err)
	}
	return value, nil
}

func newCSRFCookieFromRequest(r *http.Request, signer *cookieSigner, cookieName string) (*CSRFCookie, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("cookie %s not found in request: %w", cookieName, err)
	}

	var c *CSRFCookie
	if err = signer.Decode(cookie.Value, &c); err != nil {
		return nil, err
	}

	if c.Expired() {
		return nil, fmt.Errorf("cookie for oidc callback expired: %w", errExpiredCookie)
	}

	return c, nil
}

func (c *CSRFCookie) Expired() bool {
	return time.Now().After(time.Unix(c.ExpiresUnixSec, 0))
}

func (c *CSRFCookie) Base64() string {
	j, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(j)
}

// ############################################
// Misc Helpers
// ############################################

// deleteCookie "deletes" a cookie if that cookie exists in r.
func deleteCookie(w http.ResponseWriter, r *http.Request, cookieName, cookiePath string) {
	if _, err := r.Cookie(cookieName); err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    cookieName,
		Path:    cookiePath,
		Expires: time.Now().Add(-24 * time.Hour),
	})
}

// toMap converts a list to a set. If the list is empty, then nil is returned.
func toMap[T comparable](items []T) map[T]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[T]struct{}, len(items))
	for _, i := range items {
		m[i] = struct{}{}
	}
	return m
}

// isAuthorized returns true if the email address is found in allowedEmails
// or domain is found in allowedDomains.
func isAuthorized(email, domain string, allowedEmails, allowedDomains map[string]struct{}) bool {
	if _, foundEmail := allowedEmails[email]; foundEmail {
		return true
	}

	_, foundDomain := allowedDomains[domain]
	return foundDomain
}

// nonce generates a random 16-byte hex encoded nonce.
func nonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

// parseJWT parses a trusted JWT to extract the email and domain (hd)
// claim. This assumes that the JWT comes from a trusted source (i.e. we get it
// directly from the OIDC provider over HTTPS).
//
// The email_verified claim must be present and true, otherwise an error is
// returned.
//
// The domain value is the domain associated with the Google Workspace
// or Cloud organization of the user. Provided only if the user belongs to a
// Google Cloud organization. You must check this claim when restricting access
// to a resource to only members of certain domains. The absence of this claim
// indicates that the account does not belong to a Google hosted domain.
func parseJWT(idToken string) (email, domain string, err error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", "", errors.New("token contains an invalid number of segments")
	}

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}

	var claimMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(claims))
	dec.UseNumber()
	if err = dec.Decode(&claimMap); err != nil {
		return "", "", err
	}

	if emailVerified, _ := claimMap["email_verified"].(bool); !emailVerified {
		return "", "", errEmailNotVerified
	}
	email, _ = claimMap["email"].(string)
	if email == "" {
		return "", "", errEmailClaimMissing
	}
	domain, _ = claimMap["hd"].(string)

	return email, domain, nil
}

// redirectURI builds a URL based on the request scheme/host plus the given
// path. This is used to form the OIDC redirect URI.
func redirectURI(r *http.Request, callbackPath string) string {
	u := url.URL{
		Scheme: r.Header.Get("X-Forwarded-Proto"),
		Host:   r.Header.Get("X-Forwarded-Host"),
		Path:   callbackPath,
	}
	return u.String()
}

// csrfCookieName adds a "_csrf" suffix to the given name.
func csrfCookieName(name string) string { return name + "_csrf" }
