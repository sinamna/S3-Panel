package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ActAsHeader asks IAM to judge a request as a debug user (IAM proposal 008).
const ActAsHeader = "X-IAM-Act-As"

type actAsKey struct{}

// WithActAs returns a context whose control calls act as email. An empty email
// CLEARS it, which is how a call that must answer for the real person (listing
// the debug users themselves) opts out.
func WithActAs(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, actAsKey{}, strings.TrimSpace(email))
}

// ActAsFrom returns the debug user a context acts as, or "".
func ActAsFrom(ctx context.Context) string {
	v, _ := ctx.Value(actAsKey{}).(string)
	return v
}

func applyActAs(req *http.Request) {
	if who := ActAsFrom(req.Context()); who != "" {
		req.Header.Set(ActAsHeader, who)
	}
}

// DebugUser is one entry of IAM's GET /api/debug-users.
type DebugUser struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// WithAPIURL overrides where IAM's JSON API is (default: control_url's sibling
// "/api").
func (c *Client) WithAPIURL(u string) *Client {
	if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
		c.apiURL = u
	}
	return c
}

// ListDebugUsers asks IAM which debug users the signed-in person may act as.
// IAM answers only for a real admin in a non-production build; anything else
// comes back as an *Error the caller reads as "not available". It always
// answers for the REAL person, never for a debug user being acted as.
func (c *Client) ListDebugUsers(ctx context.Context, token string) ([]DebugUser, error) {
	req, err := http.NewRequestWithContext(WithActAs(ctx, ""), http.MethodGet, c.apiURL+"/debug-users", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list debug users: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck // response consumed below
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return nil, &Error{Status: res.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	var out struct {
		DebugUsers []DebugUser `json:"debug_users"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode debug users: %w", err)
	}
	return out.DebugUsers, nil
}

// RealIsAdmin asks IAM whether the signed-in person is an admin. IAM is the
// authority because it falls back to the Keycloak groups it synced into its own
// database, while the unified-panel client's tokens carry no groups claim for
// the panel to judge by itself.
//
// It always answers for the REAL person (act-as cleared), and reads
// real_is_admin; is_admin is only a fallback for an IAM that predates the field.
func (c *Client) RealIsAdmin(ctx context.Context, token string) (bool, error) {
	req, err := http.NewRequestWithContext(WithActAs(ctx, ""), http.MethodGet, c.apiURL+"/auth/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("ask iam who am i: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck // response consumed below
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return false, &Error{Status: res.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	var out struct {
		UserID      string `json:"user_id"`
		Email       string `json:"email"`
		RealIsAdmin *bool  `json:"real_is_admin"`
		IsAdmin     bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false, fmt.Errorf("decode iam identity: %w", err)
	}
	// /auth/me is public: a token IAM does not accept still gets a 200, just
	// anonymous and "not an admin". Reporting that as a verdict would silently
	// strip a real admin, so it is an error and the caller falls back.
	if out.UserID == "" && out.Email == "" {
		return false, errors.New("iam did not recognise the token")
	}
	if out.RealIsAdmin != nil {
		return *out.RealIsAdmin, nil
	}
	return out.IsAdmin, nil
}

func deriveAPIURL(baseURL string) string {
	if idx := strings.LastIndex(baseURL, "/"); idx > len("https:/") {
		return baseURL[:idx] + "/api"
	}
	return baseURL + "/api"
}
