package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/snapp-incubator/S3-Panel/internal/auth"
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
