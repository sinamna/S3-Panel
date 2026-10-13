package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestWithIAMAdminStoresTheAnswer(t *testing.T) {
	var gotToken string
	a := &Authenticator{ResolveAdmin: func(_ context.Context, token string) (bool, error) {
		gotToken = token
		return true, nil
	}}

	s := a.withIAMAdmin(context.Background(), Session{AccessToken: "at-1"})
	if gotToken != "at-1" || s.IAMAdmin == nil || !*s.IAMAdmin {
		t.Fatalf("token %q, IAMAdmin %v", gotToken, s.IAMAdmin)
	}
}

func TestWithIAMAdminErrorLeavesItUnknown(t *testing.T) {
	a := &Authenticator{ResolveAdmin: func(context.Context, string) (bool, error) {
		return false, errors.New("iam down")
	}}

	s := a.withIAMAdmin(context.Background(), Session{Groups: []string{"Cloud"}})
	if s.IAMAdmin != nil {
		t.Fatalf("IAMAdmin = %v; want unknown", *s.IAMAdmin)
	}
	if !s.IsRealAdmin([]string{"Cloud"}) {
		t.Error("an unknown answer must fall back to the groups claim")
	}
}

// A refresh that cannot reach IAM keeps what the sign-in learned rather than
// dropping an admin to the (empty) groups claim mid-session.
func TestWithIAMAdminKeepsPriorAnswerOnError(t *testing.T) {
	a := &Authenticator{ResolveAdmin: func(context.Context, string) (bool, error) {
		return false, errors.New("iam down")
	}}

	yes := true
	s := a.withIAMAdmin(context.Background(), Session{IAMAdmin: &yes})
	if s.IAMAdmin == nil || !*s.IAMAdmin {
		t.Fatalf("IAMAdmin = %v; want the prior true", s.IAMAdmin)
	}
}

func TestWithIAMAdminWithoutResolverIsANoop(t *testing.T) {
	s := (&Authenticator{}).withIAMAdmin(context.Background(), Session{})
	if s.IAMAdmin != nil {
		t.Fatal("no resolver must leave the answer unknown")
	}
}

// The refreshed access token is what IAM is asked about, so a change in IAM's
// verdict (the person was added to or removed from a group) lands on the next
// refresh rather than waiting for a new sign-in.
func TestRefreshReresolvesAdmin(t *testing.T) {
	var redemptions atomic.Int32
	srv := tokenEndpoint(t, &redemptions)
	a := testAuthenticator(srv.URL)
	var asked string
	a.ResolveAdmin = func(_ context.Context, token string) (bool, error) {
		asked = token
		return true, nil
	}

	next, err := a.refresh(context.Background(), Session{RefreshToken: "rt-0"})
	if err != nil {
		t.Fatal(err)
	}
	if asked != next.AccessToken || next.AccessToken == "" {
		t.Errorf("asked IAM with %q; refreshed token is %q", asked, next.AccessToken)
	}
	if next.IAMAdmin == nil || !*next.IAMAdmin {
		t.Errorf("IAMAdmin = %v", next.IAMAdmin)
	}
}
