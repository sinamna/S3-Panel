package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/snapp-incubator/S3-Panel/internal/auth"
	"github.com/snapp-incubator/S3-Panel/internal/config"
	"github.com/snapp-incubator/S3-Panel/internal/control"
)

// Review Focus 5: a credential minted for the admin must never serve the
// debug user they act as, or the reverse.
func TestCredentialCacheIsPerActingIdentity(t *testing.T) {
	admin := auth.Session{Subject: "u-admin"}
	acting := auth.Session{Subject: "u-admin", ActAs: "qa-bob@debug.iam.local"}
	if identityKey(admin) == identityKey(acting) {
		t.Fatal("the admin and the debug user they act as share a credential cache key")
	}

	cache := newCredentialCache(t.Context())
	cred := &control.Credentials{Expiration: time.Now().Add(time.Hour)}
	cache.put(identityKey(acting)+"|teh-1|b|read", cred)
	cache.put(identityKey(admin)+"|teh-1|b|read", cred)
	cache.dropIdentity(identityKey(acting))
	if _, ok := cache.get(identityKey(acting) + "|teh-1|b|read"); ok {
		t.Error("dropIdentity left the acting identity's credential")
	}
	if _, ok := cache.get(identityKey(admin) + "|teh-1|b|read"); !ok {
		t.Error("dropIdentity removed the admin's own credential")
	}
}

func TestActAsContextCarriesTheChoice(t *testing.T) {
	s := &Server{}
	var seen string
	handler := s.actAsContext()(func(c echo.Context) error {
		seen = control.ActAsFrom(c.Request().Context())
		return nil
	})
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/bucket/list", nil), httptest.NewRecorder())
	c.Set(auth.SessionContextKey, auth.Session{Subject: "u-admin", ActAs: "qa-bob@debug.iam.local"})
	if err := handler(c); err != nil {
		t.Fatal(err)
	}
	if seen != "qa-bob@debug.iam.local" {
		t.Fatalf("control calls would act as %q; want the session's choice", seen)
	}
}

// actAsServer is a panel whose control endpoint counts every request it gets,
// and whose authenticator is real (against a stub discovery document) so the
// session cookie can actually be saved.
func actAsServer(t *testing.T) (*Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ctl.Close)

	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			idp.URL, idp.URL+"/auth", idp.URL+"/token", idp.URL+"/jwks")
	}))
	t.Cleanup(idp.Close)

	a, err := auth.New(t.Context(), config.OIDCConfig{
		IssuerURL: idp.URL,
		ClientID:  "panel",
		CookieKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	client, err := control.New(ctl.URL, ctl.URL, time.Second)
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	return &Server{
		Config:      config.Config{Server: config.ServerConfig{AuthMode: config.AuthModeIAM, Region: "teh-1"}},
		auth:        a,
		control:     client,
		logger:      zap.NewNop(),
		credentials: newCredentialCache(t.Context()),
	}, &calls
}

func actAsCall(s *Server, h echo.HandlerFunc, session auth.Session) (*httptest.ResponseRecorder, error) {
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodDelete, "/api/act-as", nil), rec)
	c.Set(auth.SessionContextKey, session)
	return rec, h(c)
}

// Leaving an identity drops its cached credentials and asks IAM for nothing:
// IAM revokes per principal, which would kill other admins' credentials for the
// same shared debug user.
func TestSwitchingIdentityDropsCacheAndNeverCallsControl(t *testing.T) {
	s, calls := actAsServer(t)
	acting := auth.Session{Subject: "u-admin", ActAs: "qa-bob@debug.iam.local"}
	other := auth.Session{Subject: "u-other", ActAs: "qa-bob@debug.iam.local"}
	cred := &control.Credentials{Expiration: time.Now().Add(time.Hour)}
	s.credentials.put(identityKey(acting)+"|teh-1|b|read", cred)
	s.credentials.put(identityKey(other)+"|teh-1|b|read", cred)

	rec, err := actAsCall(s, s.handleActAsClear(), acting)
	if err != nil || rec.Code != http.StatusNoContent {
		t.Fatalf("clear: code %d err %v", rec.Code, err)
	}
	if _, ok := s.credentials.get(identityKey(acting) + "|teh-1|b|read"); ok {
		t.Error("the identity left still has a cached credential")
	}
	if _, ok := s.credentials.get(identityKey(other) + "|teh-1|b|read"); !ok {
		t.Error("another admin's credential for the same debug user was dropped")
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("switching identity made %d control calls; want none", n)
	}
}

func TestClearWhileNotActingTouchesNothing(t *testing.T) {
	s, calls := actAsServer(t)
	admin := auth.Session{Subject: "u-admin"}
	cred := &control.Credentials{Expiration: time.Now().Add(time.Hour)}
	s.credentials.put(identityKey(admin)+"|teh-1|b|read", cred)

	rec, err := actAsCall(s, s.handleActAsClear(), admin)
	if err != nil || rec.Code != http.StatusNoContent {
		t.Fatalf("clear: code %d err %v", rec.Code, err)
	}
	if _, ok := s.credentials.get(identityKey(admin) + "|teh-1|b|read"); !ok {
		t.Error("a no-op clear dropped the admin's cached credential")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a no-op clear wrote the session cookie")
	}
	if calls.Load() != 0 {
		t.Error("a no-op clear called the control endpoint")
	}
}
