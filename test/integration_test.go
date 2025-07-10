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
	protectedURL = "http://localhost/protected"
)

var cookieSecret = getEnvOrDefault("COOKIE_SECRET", "test-hmac-secret")

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

	resp, err := makeRequestWithCookie(t, "invalid-cookie-value")
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

	// Make the request.
	resp, err := makeRequestWithCookie(t, cookieSecret)
	if err != nil {
		t.Fatalf("makeRequestWithCookie failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func makeRequestWithCookie(t *testing.T, secret string) (*http.Response, error) {
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
		ExpiresUnixSec: time.Now().Add(1 * time.Hour).Unix(), // Valid for 1 hour.
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
