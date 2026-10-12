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

func TestRealIsAdmin(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"real admin", `{"real_is_admin":true,"is_admin":false}`, true},
		{"real non-admin wins over is_admin", `{"real_is_admin":false,"is_admin":true}`, false},
		{"missing real_is_admin falls back to is_admin", `{"is_admin":true}`, true},
		{"neither", `{"authenticated":true}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/auth/me" || r.Header.Get(ActAsHeader) != "" || r.Header.Get("Authorization") != "Bearer tok" {
					http.Error(w, "unexpected "+r.URL.Path, http.StatusBadRequest)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, _ := New(srv.URL+"/s3", "", time.Second)

			// Acting as someone must not leak into the question.
			got, err := c.RealIsAdmin(WithActAs(context.Background(), "someone@debug.iam.local"), "tok")
			if err != nil || got != tc.want {
				t.Fatalf("RealIsAdmin = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestRealIsAdminErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := New(srv.URL+"/s3", "", time.Second)

	if got, err := c.RealIsAdmin(context.Background(), "tok"); err == nil || got {
		t.Fatalf("RealIsAdmin = %v, %v; want an error", got, err)
	}
}
