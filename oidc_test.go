package google_oidc_auth_middleware

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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
