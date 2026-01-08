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

func TestRedirectURI(t *testing.T) {
	tests := []struct {
		name         string
		callbackPath string
		redirectHost string
		forwardedProto string
		forwardedHost  string
		want         string
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
		name           string
		secFetchMode   string
		wantStatus     int
		wantRedirect   bool
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
