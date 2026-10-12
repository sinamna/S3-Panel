package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/snapp-incubator/S3-Panel/internal/config"
	"github.com/snapp-incubator/S3-Panel/internal/control"
)

// TestIAMBucketItemCarriesResourceID: the bucket card links to the bucket's
// page in the IAM console, which is addressed by resource ID. The service key
// in that ID is not derivable from the bucket name, so it has to be passed
// through from what IAM listed rather than rebuilt here.
func TestIAMBucketItemCarriesResourceID(t *testing.T) {
	item := newIAMBucketItem(control.Bucket{
		Name:       "okd4_teh_1__payments--exports",
		ResourceID: "ceph-teh-1|bucket|okd4_teh_1__payments--exports",
	})
	if item.ResourceID != "ceph-teh-1|bucket|okd4_teh_1__payments--exports" {
		t.Errorf("ResourceID = %q, want it passed through from the listing", item.ResourceID)
	}
}

// TestConfigAdvertisesIAMConsoleURL: the SPA only offers the link when it knows
// where the console is, and only an iam-mode panel has a console to link to.
func TestConfigAdvertisesIAMConsoleURL(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{config.AuthModeIAM, true},
		{config.AuthModeS3, false},
	}
	for _, tc := range cases {
		s := &Server{Config: config.Config{Server: config.ServerConfig{
			AuthMode: tc.mode, IAMConsoleURL: "https://iam.example.com",
		}}}
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/config", nil), rec)

		if err := s.HandleConfig()(c); err != nil {
			t.Fatalf("HandleConfig: %v", err)
		}
		got := contains(rec.Body.String(), `"iam_console_url":"https://iam.example.com"`)
		if got != tc.want {
			t.Errorf("auth_mode %s: config body %s, iam_console_url advertised = %v, want %v",
				tc.mode, rec.Body.String(), got, tc.want)
		}
	}
}
