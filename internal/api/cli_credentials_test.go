package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/snapp-incubator/S3-Panel/internal/auth"
	"github.com/snapp-incubator/S3-Panel/internal/config"
	"github.com/snapp-incubator/S3-Panel/internal/control"
)

// TestCLISnippetsRenderWorkingRecipes pins the snippets to what was actually
// verified against Ceph, because they are the instructions a person follows
// verbatim — a wrong one reads as "my permissions are broken".
func TestCLISnippetsRenderWorkingRecipes(t *testing.T) {
	got := cliSnippets("IAMSTESTKEY000000001", "s3cr3t", "https://s3.example.com", "teh-1")

	for _, tool := range []string{"s3cmd", "aws", "rclone"} {
		if got[tool] == "" {
			t.Fatalf("no snippet for %q", tool)
		}
		if !strings.Contains(got[tool], "IAMSTESTKEY000000001") || !strings.Contains(got[tool], "s3cr3t") {
			t.Errorf("%s snippet does not carry the credential", tool)
		}
	}

	// s3cmd wants a bare host, not a URL; getting this wrong is a connection
	// error that looks nothing like its cause.
	if strings.Contains(got["s3cmd"], "https://") {
		t.Errorf("s3cmd host_base must be a bare host:\n%s", got["s3cmd"])
	}
	if !strings.Contains(got["s3cmd"], "use_https = True") {
		t.Errorf("s3cmd snippet lost the scheme:\n%s", got["s3cmd"])
	}

	// The AWS snippet's COMMAND must not use a tenanted bucket name: the CLI
	// rejects it before signing, and the error mentions only a regex. The comment
	// above the command says so, which is why this looks at the command alone.
	for _, line := range strings.Split(got["aws"], "\n") {
		if strings.HasPrefix(line, "aws ") && strings.Contains(line, ":<bucket>") {
			t.Errorf("the aws command uses a bucket name the CLI cannot send: %s", line)
		}
	}
	if !strings.Contains(got["aws"], "rejects") {
		t.Errorf("the aws snippet does not warn about tenanted buckets:\n%s", got["aws"])
	}
	// s3cmd is the one that does handle them, so its example must show one.
	if !strings.Contains(got["s3cmd"], "<tenant>:<bucket>") {
		t.Errorf("the s3cmd snippet should demonstrate a tenanted bucket:\n%s", got["s3cmd"])
	}
}

// TestCLISnippetsHandlePlainHTTP covers the local stack, where the gateway has no
// TLS.
func TestCLISnippetsHandlePlainHTTP(t *testing.T) {
	got := cliSnippets("AK", "SK", "http://localhost:7480", "teh-1")
	if !strings.Contains(got["s3cmd"], "use_https = False") {
		t.Errorf("plain-http endpoint still advertises TLS:\n%s", got["s3cmd"])
	}
	if !strings.Contains(got["s3cmd"], "host_base = localhost:7480") {
		t.Errorf("host_base was not derived from the endpoint:\n%s", got["s3cmd"])
	}
}

// TestCLICredentialsMintsUnpinnedAndReturnsSnippets exercises the authenticated
// path: a shell session is not "opening a bucket", and the tools this serves
// have no way to name one, so the request must go out with no Bucket at all.
func TestCLICredentialsMintsUnpinnedAndReturnsSnippets(t *testing.T) {
	var form url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<GetSessionTokenResponse><GetSessionTokenResult>
  <Credentials>
    <AccessKeyId>IAMSTESTKEY000000001</AccessKeyId>
    <SecretAccessKey>s3cr3t</SecretAccessKey>
    <SessionToken></SessionToken>
    <Expiration>2030-01-01T00:00:00Z</Expiration>
  </Credentials>
  <Endpoint>http://localhost:7480</Endpoint>
  <Region>teh-1</Region>
  <SessionId>IAMSTESTKEY000000001</SessionId>
  <ParentUser>alice@example.com</ParentUser>
</GetSessionTokenResult></GetSessionTokenResponse>`))
	}))
	defer sts.Close()

	client, err := control.New(sts.URL, sts.URL, time.Second)
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	s := &Server{
		Config:  config.Config{Server: config.ServerConfig{AuthMode: config.AuthModeIAM}},
		control: client,
		logger:  zap.NewNop(),
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cli-credentials", nil)
	rec := httptest.NewRecorder()
	c := withSession(e.NewContext(req, rec))

	if err := s.HandleCLICredentials()(c); err != nil {
		t.Fatalf("HandleCLICredentials: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if form.Get("Bucket") != "" {
		t.Errorf("a bucket was pinned (%q); a shell session cannot name one", form.Get("Bucket"))
	}
	if form.Get("Access") != accessRead {
		t.Errorf("Access = %q, want %q — a credential pasted into a shell must not default to write",
			form.Get("Access"), accessRead)
	}

	var got cliCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AccessKeyID != "IAMSTESTKEY000000001" || got.SecretAccessKey != "s3cr3t" {
		t.Fatalf("credential not returned: %+v", got)
	}
	if got.Identity != "alice@example.com" {
		t.Errorf("identity = %q, want the caller's own RGW user", got.Identity)
	}
	if got.Endpoint != "http://localhost:7480" {
		t.Errorf("endpoint = %q; a CLI user needs it for --endpoint-url", got.Endpoint)
	}
	if got.Snippets["s3cmd"] == "" {
		t.Error("no s3cmd snippet, which is the tool that handles tenanted buckets")
	}
}

// TestCLICredentialsHonoursAnExplicitWriteAsk.
func TestCLICredentialsHonoursAnExplicitWriteAsk(t *testing.T) {
	var form url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<GetSessionTokenResponse><GetSessionTokenResult><Credentials>
<AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey>
<SessionToken></SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration>
</Credentials></GetSessionTokenResult></GetSessionTokenResponse>`))
	}))
	defer sts.Close()

	client, _ := control.New(sts.URL, sts.URL, time.Second)
	s := &Server{
		Config:  config.Config{Server: config.ServerConfig{AuthMode: config.AuthModeIAM}},
		control: client,
		logger:  zap.NewNop(),
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cli-credentials?access=readwrite", nil)
	c := withSession(e.NewContext(req, httptest.NewRecorder()))

	if err := s.HandleCLICredentials()(c); err != nil {
		t.Fatalf("HandleCLICredentials: %v", err)
	}
	if form.Get("Access") != accessReadWrite {
		t.Errorf("Access = %q, want %q", form.Get("Access"), accessReadWrite)
	}
}

// TestCLICredentialsRequiresRecentAuthentication.
//
// A session cookie is a bearer token: whoever holds it is the user. That is an
// acceptable trade for browsing and a poor one for issuing a credential that
// outlives the browser and works from anywhere, so this route wants proof the
// PERSON is still there — which is what sends an attacker holding only a stolen
// cookie back to Keycloak.
func TestCLICredentialsRequiresRecentAuthentication(t *testing.T) {
	cases := []struct {
		name     string
		authTime time.Time
		wantOK   bool
	}{
		{"just authenticated", time.Now(), true},
		{"authenticated a minute ago", time.Now().Add(-time.Minute), true},
		{"authenticated an hour ago", time.Now().Add(-time.Hour), false},
		{"never recorded (a session predating the field)", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write([]byte(`<?xml version="1.0"?>
<GetSessionTokenResponse><GetSessionTokenResult><Credentials>
<AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey>
<SessionToken></SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration>
</Credentials></GetSessionTokenResult></GetSessionTokenResponse>`))
			}))
			defer sts.Close()
			client, _ := control.New(sts.URL, sts.URL, time.Second)
			s := &Server{
				Config:  config.Config{Server: config.ServerConfig{AuthMode: config.AuthModeIAM}},
				control: client,
				logger:  zap.NewNop(),
			}

			e := echo.New()
			c := e.NewContext(httptest.NewRequest(http.MethodPost, "/api/v1/cli-credentials", nil),
				httptest.NewRecorder())
			c.Set(auth.SessionContextKey, auth.Session{
				Subject: "u-alice", Email: "alice@example.com", AuthTime: tc.authTime,
			})

			err := s.HandleCLICredentials()(c)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("a freshly authenticated caller was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a stale session was issued a credential")
			}
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusUnauthorized {
				t.Fatalf("error = %v, want 401", err)
			}
			// The console needs to know to re-authenticate rather than give up.
			body, _ := he.Message.(map[string]string)
			if body["code"] != ErrCodeReauthRequired {
				t.Errorf("code = %q, want %q", body["code"], ErrCodeReauthRequired)
			}
		})
	}
}
