package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestClientKeyIsSentOnEveryControlCall: the control endpoint may demand the
// panel's client key on /s3 as well as /sts (IAM's
// awss3.require_client_key_on_s3), so every call carries it — bucket list,
// stats and policy included, not only the STS mint and sign-out.
func TestClientKeyIsSentOnEveryControlCall(t *testing.T) {
	for _, key := range []string{"panel-s3cr3t", ""} {
		var mu sync.Mutex
		seen := map[string]string{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery] = r.Header.Get(clientKeyHeader)
			mu.Unlock()
			switch {
			case r.URL.Path == "/s3/":
				_, _ = w.Write([]byte(listBucketsXML))
			case r.URL.Query().Has("stats"):
				_, _ = w.Write([]byte(`<BucketStats><Name>b</Name></BucketStats>`))
			case r.URL.Query().Has("policy"):
				_, _ = w.Write([]byte(`{"Version":"2012-10-17","Statement":[]}`))
			case r.URL.Path == "/sts/logout":
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/sts":
				_, _ = w.Write([]byte(`<GetSessionTokenResponse><GetSessionTokenResult><Credentials><AccessKeyId>AK</AccessKeyId></Credentials></GetSessionTokenResult></GetSessionTokenResponse>`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		c, err := New(srv.URL+"/s3", "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c = c.WithClientKey(key)
		ctx := context.Background()
		if _, err := c.ListBuckets(ctx, "tok"); err != nil {
			t.Fatalf("ListBuckets: %v", err)
		}
		if _, err := c.BucketStats(ctx, "tok", "b", "teh-1"); err != nil {
			t.Fatalf("BucketStats: %v", err)
		}
		if _, err := c.BucketPolicy(ctx, "tok", "b", "teh-1"); err != nil {
			t.Fatalf("BucketPolicy: %v", err)
		}
		if _, err := c.SessionCredentials(ctx, "tok", "teh-1", "", "b", "read", time.Hour); err != nil {
			t.Fatalf("SessionCredentials: %v", err)
		}
		if err := c.RevokeSessions(ctx, "tok", "teh-1", "console"); err != nil {
			t.Fatalf("RevokeSessions: %v", err)
		}
		srv.Close()

		if len(seen) != 5 {
			t.Fatalf("key %q: saw %d distinct calls, want 5: %v", key, len(seen), seen)
		}
		for call, got := range seen {
			if got != key {
				t.Errorf("key %q: %s carried %q", key, call, got)
			}
		}
	}
}

// TestControlErrorsParseBothShapes: /s3 answers errors as an S3 <Error>, /sts
// as an STS <ErrorResponse>. Both must surface the endpoint's own code and
// message, not the raw XML.
func TestControlErrorsParseBothShapes(t *testing.T) {
	bodies := map[string]string{
		"s3":  `<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>not yours</Message><RequestId>r</RequestId></Error>`,
		"sts": `<?xml version="1.0"?><ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not yours</Message></Error><RequestId>r</RequestId></ErrorResponse>`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c, err := New(srv.URL+"/s3", "", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.SessionCredentials(context.Background(), "tok", "teh-1", "", "b", "read", time.Hour)
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if ce.Status != http.StatusForbidden || ce.Code != "AccessDenied" || ce.Message != "not yours" {
				t.Errorf("error = %+v", ce)
			}
			if strings.Contains(ce.Message, "<") {
				t.Errorf("raw XML leaked into the message: %q", ce.Message)
			}
		})
	}
}
