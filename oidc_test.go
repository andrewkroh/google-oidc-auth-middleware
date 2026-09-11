package google_oidc_auth_middleware

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCookieAuthzHandler_ServeHTTP(t *testing.T) {
	const name = "cookie-name"
	const email = "john@example.com"

	h := &cookieAuthzHandler{
		debug:        log.New(os.Stdout, "["+t.Name()+"] ", 0),
		cookieName:   name,
		cookiePath:   "/",
		cookieDomain: "",
		cookieSigner: newCookieSigner("test123"),
		allowEmails: map[string]struct{}{
			email: {},
		},
		allowDomains: map[string]struct{}{
			"foo.com": {},
		},
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log("allowed")
		}),
		authN: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s", r.Context().Value("login_hint"))
		}),
	}

	t.Run("logon_hint is added for expired cookies", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/resource?foo=bar", nil)
		v, err := newAuthCookie(h.cookieSigner, time.Now().Add(-1*time.Hour), email, "")
		if err != nil {
			t.Fatal(err)
		}
		r.AddCookie(&http.Cookie{
			Name:    name,
			Expires: time.Now().Add(time.Hour),
			Value:   v,
		})

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		body, err := io.ReadAll(w.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		if email != string(body) {
			t.Error("login_hint was not passed to the authN handler")
		}
	})
}

// recordingHandler records whether it was called and the request it received.
type recordingHandler struct {
	called bool
	req    *http.Request
}

func (h *recordingHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.called = true
	h.req = r
}

func TestCookieAuthzHandler_AllowAllAuthenticatedUsers(t *testing.T) {
	const name = "cookie-name"
	const secret = "test123"

	newHandler := func(allowAll bool, allowEmails, allowDomains map[string]struct{}) (h *cookieAuthzHandler, next, authN *recordingHandler) {
		next, authN = &recordingHandler{}, &recordingHandler{}
		h = &cookieAuthzHandler{
			debug:        log.New(os.Stdout, "["+t.Name()+"] ", 0),
			cookieName:   name,
			cookiePath:   "/",
			cookieSigner: newCookieSigner(secret),
			allowEmails:  allowEmails,
			allowDomains: allowDomains,
			allowAll:     allowAll,
			next:         next,
			authN:        authN,
		}
		return h, next, authN
	}

	newRequest := func(t *testing.T, cookieValue string) *http.Request {
		t.Helper()
		r := httptest.NewRequest("GET", "/resource", nil)
		if cookieValue != "" {
			r.AddCookie(&http.Cookie{Name: name, Value: cookieValue})
		}
		return r
	}

	signedCookie := func(t *testing.T, signer *cookieSigner, expires time.Time, email, domain string) string {
		t.Helper()
		v, err := newAuthCookie(signer, expires, email, domain)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	assertAuthN := func(t *testing.T, next, authN *recordingHandler) {
		t.Helper()
		if next.called {
			t.Error("next handler was called, want only authN")
		}
		if !authN.called {
			t.Error("authN handler was not called")
		}
	}

	t.Run("unlisted user with valid cookie is allowed", func(t *testing.T) {
		h, next, authN := newHandler(true, nil, nil)
		r := newRequest(t, signedCookie(t, h.cookieSigner, time.Now().Add(time.Hour), "stranger@gmail.com", ""))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if !next.called {
			t.Fatal("next handler was not called")
		}
		if authN.called {
			t.Error("authN handler was called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
		}
		if got := next.req.Header.Get("X-Forwarded-User"); got != "stranger@gmail.com" {
			t.Errorf("X-Forwarded-User = %q, want %q", got, "stranger@gmail.com")
		}
	})

	t.Run("expired cookie still authenticates", func(t *testing.T) {
		h, next, authN := newHandler(true, nil, nil)
		r := newRequest(t, signedCookie(t, h.cookieSigner, time.Now().Add(-time.Hour), "stranger@gmail.com", ""))

		h.ServeHTTP(httptest.NewRecorder(), r)

		assertAuthN(t, next, authN)
		if authN.req != nil {
			if got, _ := authN.req.Context().Value("login_hint").(string); got != "stranger@gmail.com" {
				t.Errorf("login_hint = %q, want %q", got, "stranger@gmail.com")
			}
		}
	})

	t.Run("no cookie still authenticates", func(t *testing.T) {
		h, next, authN := newHandler(true, nil, nil)
		r := newRequest(t, "")

		h.ServeHTTP(httptest.NewRecorder(), r)

		assertAuthN(t, next, authN)
	})

	t.Run("tampered cookie still authenticates", func(t *testing.T) {
		h, _, _ := newHandler(true, nil, nil)
		valid := signedCookie(t, h.cookieSigner, time.Now().Add(time.Hour), "stranger@gmail.com", "")
		sig, _, _ := strings.Cut(valid, ".")
		forgedPayload := (&AuthCookie{
			ExpiresUnixSec: time.Now().Add(time.Hour).Unix(),
			Email:          "attacker@evil.com",
		}).Base64()

		tests := []struct {
			name  string
			value string
		}{
			{
				name:  "payload replaced under original signature",
				value: sig + "." + forgedPayload,
			},
			{
				name:  "signed with a different secret",
				value: signedCookie(t, newCookieSigner("wrong-secret"), time.Now().Add(time.Hour), "stranger@gmail.com", ""),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				h, next, authN := newHandler(true, nil, nil)
				r := newRequest(t, tt.value)

				h.ServeHTTP(httptest.NewRecorder(), r)

				assertAuthN(t, next, authN)
			})
		}
	})

	t.Run("allowlist mode denies unlisted user", func(t *testing.T) {
		h, next, authN := newHandler(false,
			map[string]struct{}{"john@example.com": {}},
			map[string]struct{}{"foo.com": {}})
		r := newRequest(t, signedCookie(t, h.cookieSigner, time.Now().Add(time.Hour), "stranger@gmail.com", "bar.com"))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
		}
		if next.called {
			t.Error("next handler was called for unlisted user")
		}
		if authN.called {
			t.Error("authN handler was called for authenticated but unauthorized user")
		}
	})

	t.Run("allowlist mode allows listed user", func(t *testing.T) {
		h, next, _ := newHandler(false,
			map[string]struct{}{"john@example.com": {}},
			map[string]struct{}{"foo.com": {}})
		r := newRequest(t, signedCookie(t, h.cookieSigner, time.Now().Add(time.Hour), "jane@foo.com", "foo.com"))

		h.ServeHTTP(httptest.NewRecorder(), r)

		if !next.called {
			t.Fatal("next handler was not called for listed domain")
		}
		if got := next.req.Header.Get("X-Forwarded-User"); got != "jane@foo.com" {
			t.Errorf("X-Forwarded-User = %q, want %q", got, "jane@foo.com")
		}
	})
}

func TestIsAuthorized(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		domain       string
		allowEmails  map[string]struct{}
		allowDomains map[string]struct{}
		allowAll     bool
		want         bool
	}{
		{
			name:     "allowAll authorizes user with no hd claim on no list",
			email:    "stranger@gmail.com",
			allowAll: true,
			want:     true,
		},
		{
			name:     "allowAll authorizes workspace user",
			email:    "user@corp.com",
			domain:   "corp.com",
			allowAll: true,
			want:     true,
		},
		{
			name:     "allowAll never authorizes empty email",
			allowAll: true,
			want:     false,
		},
		{
			name:         "empty email with matching domain is not authorized",
			domain:       "corp.com",
			allowDomains: map[string]struct{}{"corp.com": {}},
			want:         false,
		},
		{
			name:         "unlisted user is not authorized",
			email:        "stranger@gmail.com",
			allowEmails:  map[string]struct{}{"user@corp.com": {}},
			allowDomains: map[string]struct{}{"corp.com": {}},
			want:         false,
		},
		{
			name:         "domain match",
			email:        "user@corp.com",
			domain:       "corp.com",
			allowDomains: map[string]struct{}{"corp.com": {}},
			want:         true,
		},
		{
			name:        "email match with no hd claim",
			email:       "other@corp.com",
			allowEmails: map[string]struct{}{"other@corp.com": {}},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthorized(tt.email, tt.domain, tt.allowEmails, tt.allowDomains, tt.allowAll)
			if got != tt.want {
				t.Errorf("isAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAuthCookieFromRequest_MultipleCookies(t *testing.T) {
	signer := newCookieSigner("test-secret")
	cookieName := "oidc_auth"

	t.Run("uses valid cookie when first cookie is expired", func(t *testing.T) {
		// Create an expired cookie (first in order)
		expiredValue, _ := newAuthCookie(signer, time.Now().Add(-1*time.Hour), "expired@example.com", "")
		// Create a valid cookie (second in order)
		validValue, _ := newAuthCookie(signer, time.Now().Add(1*time.Hour), "valid@example.com", "")

		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: expiredValue})
		r.AddCookie(&http.Cookie{Name: cookieName, Value: validValue})

		ac, _, err := newAuthCookieFromRequest(r, signer, cookieName)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if ac.Email != "valid@example.com" {
			t.Errorf("expected valid@example.com, got %s", ac.Email)
		}
	})

	t.Run("uses valid cookie when second cookie is expired", func(t *testing.T) {
		// Create a valid cookie (first in order)
		validValue, _ := newAuthCookie(signer, time.Now().Add(1*time.Hour), "valid@example.com", "")
		// Create an expired cookie (second in order)
		expiredValue, _ := newAuthCookie(signer, time.Now().Add(-1*time.Hour), "expired@example.com", "")

		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: validValue})
		r.AddCookie(&http.Cookie{Name: cookieName, Value: expiredValue})

		ac, _, err := newAuthCookieFromRequest(r, signer, cookieName)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if ac.Email != "valid@example.com" {
			t.Errorf("expected valid@example.com, got %s", ac.Email)
		}
	})

	t.Run("returns login_hint when all cookies are expired", func(t *testing.T) {
		expiredValue1, _ := newAuthCookie(signer, time.Now().Add(-2*time.Hour), "first@example.com", "")
		expiredValue2, _ := newAuthCookie(signer, time.Now().Add(-1*time.Hour), "second@example.com", "")

		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: expiredValue1})
		r.AddCookie(&http.Cookie{Name: cookieName, Value: expiredValue2})

		_, loginHint, err := newAuthCookieFromRequest(r, signer, cookieName)
		if err == nil {
			t.Fatal("expected error for expired cookies")
		}
		// Should return the last email seen as login_hint
		if loginHint != "second@example.com" {
			t.Errorf("expected login_hint second@example.com, got %s", loginHint)
		}
	})
}

func TestRedirectURI(t *testing.T) {
	tests := []struct {
		name           string
		callbackPath   string
		redirectHost   string
		forwardedProto string
		forwardedHost  string
		want           string
	}{
		{
			name:           "default behavior without redirect host",
			callbackPath:   "/oidc/callback",
			redirectHost:   "",
			forwardedProto: "https",
			forwardedHost:  "app1.example.com",
			want:           "https://app1.example.com/oidc/callback",
		},
		{
			name:           "with redirect host override",
			callbackPath:   "/oidc/callback",
			redirectHost:   "auth.example.com",
			forwardedProto: "https",
			forwardedHost:  "app1.example.com",
			want:           "https://auth.example.com/oidc/callback",
		},
		{
			name:           "custom callback path with redirect host",
			callbackPath:   "/custom/path",
			redirectHost:   "central.example.com",
			forwardedProto: "https",
			forwardedHost:  "subdomain.example.com",
			want:           "https://central.example.com/custom/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			r.Header.Set("X-Forwarded-Host", tt.forwardedHost)

			got := redirectURI(r, tt.callbackPath, tt.redirectHost)
			if got != tt.want {
				t.Errorf("redirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config without domain",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					Emails: []string{"user@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with domain starting with dot",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
					Domain:   ".example.com",
				},
				Authorized: AuthorizedConfig{
					Emails: []string{"user@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid domain without leading dot",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
					Domain:   "example.com",
				},
				Authorized: AuthorizedConfig{
					Emails: []string{"user@example.com"},
				},
			},
			wantErr:     true,
			errContains: "must start with a dot",
		},
		{
			name: "redirectHost without cookie.domain",
			config: &Config{
				OIDC: OIDCConfig{
					RedirectHost: "auth.example.com",
				},
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
					// Domain is missing
				},
				Authorized: AuthorizedConfig{
					Emails: []string{"user@example.com"},
				},
			},
			wantErr:     true,
			errContains: "cookie.domain is required when using a central redirect URI",
		},
		{
			name: "valid config with both redirectHost and cookie.domain",
			config: &Config{
				OIDC: OIDCConfig{
					RedirectHost: "auth.example.com",
				},
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
					Domain:   ".example.com",
				},
				Authorized: AuthorizedConfig{
					Emails: []string{"user@example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "allowAllAuthenticatedUsers without allowlists",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
				},
			},
			wantErr: false,
		},
		{
			name: "allowAllAuthenticatedUsers with emails",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
					Emails:                     []string{"user@example.com"},
				},
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		{
			name: "allowAllAuthenticatedUsers with domains",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
					Domains:                    []string{"example.com"},
				},
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		{
			name: "allowAllAuthenticatedUsers with emails and domains",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
					Emails:                     []string{"user@example.com"},
					Domains:                    []string{"example.com"},
				},
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		{
			name: "no authorized config",
			config: &Config{
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: false,
				},
			},
			wantErr:     true,
			errContains: "allowAllAuthenticatedUsers",
		},
		{
			name: "allowAllAuthenticatedUsers does not skip cookie.secret validation",
			config: &Config{
				Cookie: CookieConfig{
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
				},
			},
			wantErr:     true,
			errContains: "cookie.secret must be configured",
		},
		{
			name: "allowAllAuthenticatedUsers does not skip redirectHost validation",
			config: &Config{
				OIDC: OIDCConfig{
					RedirectHost: "auth.example.com",
				},
				Cookie: CookieConfig{
					Secret:   "test-secret",
					Duration: "24h",
					SameSite: "Lax",
				},
				Authorized: AuthorizedConfig{
					AllowAllAuthenticatedUsers: true,
				},
			},
			wantErr:     true,
			errContains: "cookie.domain is required when using a central redirect URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), tt.config, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("New() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestAuthnRedirectHandler_XHRRequests(t *testing.T) {
	config := &Config{
		OIDC: OIDCConfig{
			ClientID:     "test-client-id",
			CallbackPath: "/oidc/callback",
		},
		Cookie: CookieConfig{
			Name:     "oidc_auth",
			Path:     "/",
			Secret:   "test-secret",
			Duration: "24h",
			sameSite: http.SameSiteLaxMode,
		},
	}

	h := &authnRedirectHandler{
		debug:                 log.New(io.Discard, "", 0),
		config:                config,
		signer:                newCookieSigner(config.Cookie.Secret),
		authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	}

	tests := []struct {
		name         string
		secFetchMode string
		wantStatus   int
		wantRedirect bool
	}{
		{
			name:         "navigate mode triggers redirect",
			secFetchMode: "navigate",
			wantStatus:   http.StatusTemporaryRedirect,
			wantRedirect: true,
		},
		{
			name:         "cors mode returns 401",
			secFetchMode: "cors",
			wantStatus:   http.StatusUnauthorized,
			wantRedirect: false,
		},
		{
			name:         "same-origin mode returns 401",
			secFetchMode: "same-origin",
			wantStatus:   http.StatusUnauthorized,
			wantRedirect: false,
		},
		{
			name:         "no-cors mode returns 401",
			secFetchMode: "no-cors",
			wantStatus:   http.StatusUnauthorized,
			wantRedirect: false,
		},
		{
			name:         "empty header triggers redirect (legacy browser)",
			secFetchMode: "",
			wantStatus:   http.StatusTemporaryRedirect,
			wantRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/resource", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "app.example.com")
			if tt.secFetchMode != "" {
				r.Header.Set("Sec-Fetch-Mode", tt.secFetchMode)
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}

			hasLocation := w.Header().Get("Location") != ""
			if hasLocation != tt.wantRedirect {
				t.Errorf("got redirect=%v, want redirect=%v", hasLocation, tt.wantRedirect)
			}

			// For non-navigate requests, verify no CSRF cookie is set
			if !tt.wantRedirect {
				cookies := w.Result().Cookies()
				for _, c := range cookies {
					if c.Name == "oidc_auth_csrf" {
						t.Error("CSRF cookie should not be set for XHR requests")
					}
				}
			}
		})
	}
}
