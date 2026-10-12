package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestActAsHeaderRidesOnEveryControlCall(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(ActAsHeader))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/s3", srv.URL+"/sts", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctx := WithActAs(context.Background(), "qa-bob@debug.iam.local")
	_, _ = c.ListBuckets(ctx, "tok")
	_ = c.RevokeSessions(ctx, "tok", "teh-1", "console")
	_, _ = c.ListBuckets(WithActAs(ctx, ""), "tok") // cleared

	want := []string{"qa-bob@debug.iam.local", "qa-bob@debug.iam.local", ""}
	if len(got) != len(want) {
		t.Fatalf("calls = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d header = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestListDebugUsersNeverActs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/debug-users" || r.Header.Get(ActAsHeader) != "" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"debug_users":[{"email":"qa-bob@debug.iam.local","username":"qa-bob"}]}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL+"/s3", "", time.Second)

	users, err := c.ListDebugUsers(WithActAs(context.Background(), "someone@debug.iam.local"), "tok")
	if err != nil || len(users) != 1 || users[0].Email != "qa-bob@debug.iam.local" {
		t.Fatalf("ListDebugUsers = %+v, %v", users, err)
	}
}
