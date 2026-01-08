// Licensed to Andrew Kroh under one or more agreements.
// Andrew Kroh licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	protectedURL              = "http://localhost/protected"
	protectedPromptURL        = "http://localhost/protected-prompt"
	protectedMultisubdomainURL = "http://localhost/protected-multisubdomain"
)

var cookieSecret = getEnvOrDefault("COOKIE_SECRET", "test-hmac-secret")

func TestMain(m *testing.M) {
	if os.Getenv("INTEG_TEST") == "" {
		fmt.Println("Skipping integration tests: INTEG_TEST environment variable not set.")
		return
	}

	os.Exit(m.Run())
}

// TestUnauthorizedAccess verifies that unauthorized requests are redirected to Google OAuth.
func TestUnauthorizedAccess(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we want to examine them.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(protectedURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedURL, err)
	}
	defer resp.Body.Close()

	// Should get a redirect to Google OAuth.
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	for _, want := range []string{
		"accounts.google.com/o/oauth2/v2/auth",
		"client_id=",
		"redirect_uri=",
		"response_type=code",
		"scope=openid+email",
	} {
		if !strings.Contains(location, want) {
			t.Errorf("Location header got %q, want to contain %q", location, want)
		}
	}

	// Verify CSRF cookie is set.
	var csrfCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if strings.HasSuffix(cookie.Name, "_csrf") {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}
	if got, want := csrfCookie.Path, "/protected/oidc/callback"; got != want {
		t.Errorf("CSRF cookie path got %q, want %q", got, want)
	}
	if !csrfCookie.HttpOnly {
		t.Error("CSRF cookie HttpOnly got false, want true")
	}
	if got, want := csrfCookie.SameSite, http.SameSiteLaxMode; got != want {
		t.Errorf("CSRF cookie SameSite got %v, want %v", got, want)
	}
}

// TestUnauthorizedAccessWithPrompt verifies that unauthorized requests are redirected
// to Google OAuth with the prompt parameter.
func TestUnauthorizedAccessWithPrompt(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we want to examine them.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(protectedPromptURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedPromptURL, err)
	}
	defer resp.Body.Close()

	// Should get a redirect to Google OAuth.
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "prompt=select_account") {
		t.Errorf("Location header got %q, want to contain 'prompt=select_account'", location)
	}
}

// TestOAuthCallback tests the OAuth callback handling.
func TestOAuthCallback(t *testing.T) {
	t.Parallel()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New failed: %v", err)
	}

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// First, get the initial redirect to capture CSRF cookie.
	resp, err := client.Get(protectedURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedURL, err)
	}
	resp.Body.Close()

	// Parse the redirect URL to get state parameter.
	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", location, err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" {
		t.Fatal("state parameter not found in redirect URL")
	}

	// Simulate callback with invalid code (should fail gracefully).
	callbackURL := fmt.Sprintf("%s/oidc/callback?code=invalid&state=%s", protectedURL, state)
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", callbackURL, err)
	}
	defer resp.Body.Close()

	// Should get an error response (400 or 401).
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("StatusCode got %d, want a 4xx status code", resp.StatusCode)
	}
}

// TestBadSignatureCookie tests that a cookie with an invalid signature is rejected.
func TestBadSignatureCookie(t *testing.T) {
	t.Parallel()

	resp, err := makeRequestWithCookie(t, "invalid-cookie-value", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("makeRequestWithCookie failed: %v", err)
	}
	defer resp.Body.Close()

	// Should still redirect to OAuth (invalid cookie ignored).
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "accounts.google.com") {
		t.Errorf("Location header got %q, want to contain %q", location, "accounts.google.com")
	}
}

// TestValidCookie tests cookie-based authentication with a valid cookie.
func TestValidCookie(t *testing.T) {
	t.Parallel()

	// Make the request with a valid expiration time.
	resp, err := makeRequestWithCookie(t, cookieSecret, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("makeRequestWithCookie failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestExpiredCookieWithLoginHint tests that an expired cookie triggers OAuth
// redirect with login_hint query parameter containing the user's email from the
// cookie.
func TestExpiredCookieWithLoginHint(t *testing.T) {
	t.Parallel()

	// Make the request with an expired cookie.
	resp, err := makeRequestWithCookie(t, cookieSecret, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("makeRequestWithCookie failed: %v", err)
	}
	defer resp.Body.Close()

	// Should get a redirect to Google OAuth (expired cookie should trigger re-auth).
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("Location header is empty")
	}

	// Parse the redirect URL to check for login_hint parameter.
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL %q: %v", location, err)
	}

	// Verify that login_hint query parameter is present and contains the user's email.
	testEmail := "user@example.com" // This matches the email used in makeRequestWithCookie
	loginHint := redirectURL.Query().Get("login_hint")
	if loginHint == "" {
		t.Error("login_hint query parameter not found in redirect URL")
	} else if loginHint != testEmail {
		t.Errorf("login_hint got %q, want %q", loginHint, testEmail)
	}

	// Also verify other expected OAuth parameters are present.
	for _, want := range []string{
		"accounts.google.com/o/oauth2/v2/auth",
		"client_id=",
		"redirect_uri=",
		"response_type=code",
		"scope=openid+email",
	} {
		if !strings.Contains(location, want) {
			t.Errorf("Location header got %q, want to contain %q", location, want)
		}
	}
}

// TestCookieDomainAttribute tests that cookies have the Domain attribute set
// when cookie.domain is configured in the middleware. This is important for
// multi-subdomain authentication scenarios.
func TestCookieDomainAttribute(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we want to examine them.
			return http.ErrUseLastResponse
		},
	}

	// Test the multi-subdomain service which has cookie.domain configured
	resp, err := client.Get(protectedMultisubdomainURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedMultisubdomainURL, err)
	}
	defer resp.Body.Close()

	// Should get a redirect to Google OAuth.
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	// Verify CSRF cookie Domain attribute.
	var csrfCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if strings.HasSuffix(cookie.Name, "_csrf") {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}

	// The multi-subdomain service should have cookie.domain set via COOKIE_DOMAIN env var.
	// Note: Go's http.Cookie strips the leading dot when sending Set-Cookie headers,
	// so we expect "localhost" even though the config has ".localhost".
	configuredDomain := getEnvOrDefault("COOKIE_DOMAIN", ".localhost")
	expectedDomain := strings.TrimPrefix(configuredDomain, ".")
	if csrfCookie.Domain != expectedDomain {
		t.Errorf("CSRF cookie Domain got %q, want %q (configured as %q, leading dot stripped by Go)", csrfCookie.Domain, expectedDomain, configuredDomain)
	}

	// Verify other cookie attributes are still correct.
	if got, want := csrfCookie.Path, "/protected-multisubdomain/oidc/callback"; got != want {
		t.Errorf("CSRF cookie path got %q, want %q", got, want)
	}
	if !csrfCookie.HttpOnly {
		t.Error("CSRF cookie HttpOnly got false, want true")
	}
	if got, want := csrfCookie.SameSite, http.SameSiteLaxMode; got != want {
		t.Errorf("CSRF cookie SameSite got %v, want %v", got, want)
	}
}

// TestRedirectURIWithRedirectHost tests that the redirect_uri parameter uses
// the configured redirectHost when oidc.redirectHost is set. This verifies
// the multi-subdomain feature where all auth flows use a central callback URL.
func TestRedirectURIWithRedirectHost(t *testing.T) {
	t.Parallel()

	// This test verifies the redirect_uri in the OAuth authorization URL.
	// The multi-subdomain service should use oidc.redirectHost for the redirect_uri.

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test the multi-subdomain service which has oidc.redirectHost configured
	resp, err := client.Get(protectedMultisubdomainURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedMultisubdomainURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL %q: %v", location, err)
	}

	redirectURI := redirectURL.Query().Get("redirect_uri")
	if redirectURI == "" {
		t.Fatal("redirect_uri parameter not found in OAuth URL")
	}

	// Parse the redirect_uri to check its host.
	parsedRedirectURI, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("Failed to parse redirect_uri %q: %v", redirectURI, err)
	}

	// The multi-subdomain service should use the REDIRECT_HOST env var
	expectedHost := getEnvOrDefault("REDIRECT_HOST", "auth.localhost")
	if parsedRedirectURI.Host != expectedHost {
		t.Errorf("redirect_uri host got %q, want %q (REDIRECT_HOST env var)", parsedRedirectURI.Host, expectedHost)
	}

	// Verify the path is still correct.
	expectedPath := "/protected-multisubdomain/oidc/callback"
	if parsedRedirectURI.Path != expectedPath {
		t.Errorf("redirect_uri path got %q, want %q", parsedRedirectURI.Path, expectedPath)
	}

	t.Logf("redirect_uri: %s", redirectURI)
}

// TestMultisubdomainBackwardCompatibility verifies that the standard protected
// service (without multi-subdomain config) still works as before.
func TestMultisubdomainBackwardCompatibility(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test the standard protected service (no redirectHost or cookie.domain)
	resp, err := client.Get(protectedURL)
	if err != nil {
		t.Fatalf("GET %q failed: %v", protectedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL %q: %v", location, err)
	}

	redirectURI := redirectURL.Query().Get("redirect_uri")
	if redirectURI == "" {
		t.Fatal("redirect_uri parameter not found in OAuth URL")
	}

	parsedRedirectURI, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("Failed to parse redirect_uri %q: %v", redirectURI, err)
	}

	// Without redirectHost configured, should use the request's host
	if parsedRedirectURI.Host != "localhost" {
		t.Errorf("redirect_uri host got %q, want %q (no redirectHost)", parsedRedirectURI.Host, "localhost")
	}

	// Check CSRF cookie has no Domain attribute (backward compatible)
	var csrfCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if strings.HasSuffix(cookie.Name, "_csrf") {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}

	if csrfCookie.Domain != "" {
		t.Errorf("CSRF cookie Domain got %q, want empty (backward compatible)", csrfCookie.Domain)
	}
}

func makeRequestWithCookie(t *testing.T, secret string, expirationTime time.Time) (*http.Response, error) {
	t.Helper()

	// Create HTTP client with cookie jar.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar.New failed: %w", err)
	}

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create auth cookie data for user@example.com.
	authCookie := struct {
		ExpiresUnixSec int64  `json:"exp"`
		Email          string `json:"email"`
		Domain         string `json:"domain,omitempty"`
	}{
		ExpiresUnixSec: expirationTime.Unix(),
		Email:          "user@example.com",
		Domain:         "example.com",
	}

	// Convert to JSON.
	cookieJSON, err := json.Marshal(authCookie)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	// Base64 encode the JSON.
	cookieB64 := base64.RawURLEncoding.EncodeToString(cookieJSON)

	// Create HMAC signature using the same algorithm as cookieSigner.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(cookieB64))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Combine signature and cookie data.
	forgedCookie := signature + "." + cookieB64

	// Create request to protected URL.
	req, err := http.NewRequest("GET", protectedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest failed: %w", err)
	}

	// Add the forged cookie.
	cookie := &http.Cookie{
		Name:  "oidc_auth", // Default cookie name.
		Value: forgedCookie,
		Path:  "/",
	}
	req.AddCookie(cookie)

	// Make the request.
	return client.Do(req)
}

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
