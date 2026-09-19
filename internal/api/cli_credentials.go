package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/snapp-incubator/S3-Panel/internal/auth"
)

// Handing the signed-in person a credential they can paste into a shell.
//
// This is the panel's only route that deliberately returns a secret to the
// browser, so it is worth being explicit about why that is acceptable here and
// was not before. A session credential used to be a subuser of the bucket's
// OWNER — a shared team account — so giving one to a person meant giving them
// everything that account owned, for the credential's whole lifetime. A
// credential is now an ephemeral key on the person's OWN RGW identity, reaching
// exactly the buckets IAM grants them. Showing it to them reveals nothing they
// did not already have.
//
// Two rules still apply: it must be an explicit action (never part of a page
// load), and it is audited on the IAM side, which records the mint with the
// caller, the level and the buckets it had to grant on.

// cliCredentialTTL is how long a credential handed to a shell lives.
//
// Longer than the console's own hour because a person pasting this into a
// terminal cannot be silently refreshed the way the panel's cache is, and
// shorter than the 12h cap because it is going to sit in a shell profile.
const cliCredentialTTL = 4 * time.Hour

// freshAuthWindow is how recently the person must have proved who they are
// before this route will hand them a credential.
//
// A session cookie is a bearer token: whoever has it is the user. That is a fine
// trade for browsing, and a poor one for issuing a credential that outlives the
// browser and works from anywhere. Requiring a recent authentication means a
// stolen cookie alone is not enough — the attacker also has to get past
// Keycloak, which is where the second factor lives.
//
// Long enough that someone doing a few things in a sitting is not prompted
// twice; short enough that a cookie lifted from a closed laptop is useless.
const freshAuthWindow = 5 * time.Minute

// ErrCodeReauthRequired is returned so the console can send the person through
// /auth/login?prompt=login rather than showing them a bare 401.
const ErrCodeReauthRequired = "reauth_required"

// cliCredentialsResponse is what the UI renders.
type cliCredentialsResponse struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	Endpoint        string    `json:"endpoint"`
	Region          string    `json:"region"`
	Identity        string    `json:"identity"`
	Expiration      time.Time `json:"expiration"`
	// Snippets are ready-to-paste configuration, keyed by tool.
	Snippets map[string]string `json:"snippets"`
	// Note explains the one thing that will otherwise look like a bug.
	Note string `json:"note"`
}

// HandleCLICredentials mints a credential for use outside the panel.
//
// No bucket is pinned: a shell session is not "opening a bucket", and the tools
// this serves have no way to say which one. The credential is therefore granted
// across everything the caller is entitled to in the region, which the control
// endpoint caps.
func (s *Server) HandleCLICredentials() echo.HandlerFunc {
	return func(c echo.Context) error {
		if !s.Config.Server.IsIAMMode() {
			return echo.NewHTTPError(http.StatusNotImplemented,
				"command-line credentials are only available when the panel authenticates through IAM")
		}
		session, ok := auth.SessionFrom(c)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
		}

		// Re-authentication, not just a live session. See freshAuthWindow.
		if !session.FreshlyAuthenticated(freshAuthWindow) {
			return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
				"code":    ErrCodeReauthRequired,
				"message": "Confirm your identity before a command-line credential is issued.",
				"login":   "/auth/login?prompt=login",
			})
		}

		region := s.requestRegion(c)

		// The level is the caller's ask, clamped by IAM to what their grants
		// allow. "read" is the default so a credential pasted into a shell cannot
		// delete anything unless the person deliberately asked for that.
		access := accessRead
		if strings.EqualFold(c.QueryParam("access"), accessReadWrite) {
			access = accessReadWrite
		}

		cred, err := s.control.SessionCredentials(
			c.Request().Context(), session.AccessToken, region, "", "", access, cliCredentialTTL)
		if err != nil {
			return controlError(err, "could not issue a command-line credential")
		}

		endpoint := cred.Endpoint
		if endpoint == "" {
			endpoint = s.Config.ObjectStorage.URL
		}

		return c.JSON(http.StatusOK, cliCredentialsResponse{
			AccessKeyID:     cred.AccessKeyID,
			SecretAccessKey: cred.SecretAccessKey,
			Endpoint:        endpoint,
			Region:          cred.Region,
			Identity:        cred.ParentUser,
			Expiration:      cred.Expiration,
			Snippets:        cliSnippets(cred.AccessKeyID, cred.SecretAccessKey, endpoint, cred.Region),
			Note: "Team buckets are addressed as <tenant>:<bucket>. The AWS CLI rejects that name " +
				"before it signs anything, so use s3cmd, rclone or mc for them; the AWS CLI works " +
				"for buckets without a tenant.",
		})
	}
}

// cliSnippets renders configuration for the tools that actually work.
//
// The recipes here are the ones verified end to end against Mimic (see
// docs/s3-cli-access.md). Rendering them from the same place the credential is
// issued is deliberate: a recipe kept somewhere else drifts from what the
// endpoint hands out, and the failure mode is a person believing their
// permissions are wrong.
func cliSnippets(accessKey, secret, endpoint, region string) map[string]string {
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	useHTTPS := "True"
	if strings.HasPrefix(endpoint, "http://") {
		useHTTPS = "False"
	}

	return map[string]string{
		"s3cmd": fmt.Sprintf(`# ~/.s3cfg  — works for every bucket, including team (tenanted) ones
[default]
access_key = %s
secret_key = %s
host_base = %s
host_bucket = %s
use_https = %s

# s3cmd ls 's3://<tenant>:<bucket>'`, accessKey, secret, host, host, useHTTPS),

		"aws": fmt.Sprintf(`# Buckets WITHOUT a tenant only — the AWS CLI rejects "<tenant>:<bucket>".
export AWS_ACCESS_KEY_ID=%s
export AWS_SECRET_ACCESS_KEY=%s
export AWS_DEFAULT_REGION=%s

aws --endpoint-url %s s3 ls s3://<bucket>`, accessKey, secret, region, endpoint),

		"rclone": fmt.Sprintf(`# ~/.config/rclone/rclone.conf
[snapp]
type = s3
provider = Ceph
access_key_id = %s
secret_access_key = %s
endpoint = %s
region = %s

# rclone ls snapp:<tenant>:<bucket>`, accessKey, secret, endpoint, region),
	}
}

// csrfMiddleware protects the credential route.
//
// Double-submit: the token is issued in a cookie by the GET below and must be
// echoed in the X-CSRF-Token header on the POST. A cross-origin page can cause
// the cookie to be SENT but cannot READ it, so it cannot produce the header —
// and setting a custom header forces a preflight that CORS refuses.
//
// The cookie is SameSite=Strict and HttpOnly=false on purpose: the console's own
// script has to read it to build the header, and Strict keeps it off
// cross-origin requests entirely.
func (s *Server) csrfMiddleware() echo.MiddlewareFunc {
	return middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "header:X-CSRF-Token",
		CookieName:     "s3panel_csrf",
		CookiePath:     "/",
		CookieHTTPOnly: false,
		CookieSameSite: http.SameSiteStrictMode,
		CookieSecure:   s.Config.Server.IsIAMMode(),
	})
}

// HandleCSRFToken hands the console the token it must echo on the POST.
func (s *Server) HandleCSRFToken() echo.HandlerFunc {
	return func(c echo.Context) error {
		token, _ := c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
		return c.JSON(http.StatusOK, map[string]string{"csrf_token": token})
	}
}
