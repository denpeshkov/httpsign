package httpsign

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/denpeshkov/httpsign/hmac"
)

const (
	key = "test-key"
	kid = "test-key-id"
)

func TestQueryEncode(t *testing.T) {
	tests := []struct {
		values  url.Values
		encoded string
	}{
		{nil, ""},
		{url.Values{}, ""},
		{url.Values{"k": {"v"}}, "k=v"},
		{url.Values{"k1": {"v1"}, "k2": {"v2"}}, "k1=v1&k2=v2"},
		{url.Values{"k1": {"v1_1", "v1_2"}, "k2": {"v2"}}, "k1=v1_1&k1=v1_2&k2=v2"},
		{url.Values{"k1": {"v1_2", "v1_1"}, "k2": {"v2"}}, "k1=v1_1&k1=v1_2&k2=v2"},
		{url.Values{"k1": {"v1"}, "k2": {"v2"}, "k3": {"v3"}}, "k1=v1&k2=v2&k3=v3"},
		{url.Values{"k1": {"v1"}, "k2": {"v2_1", "v2_2"}, "k3": {"v3_1", "v3_2"}}, "k1=v1&k2=v2_1&k2=v2_2&k3=v3_1&k3=v3_2"},
		{url.Values{"k1": {"v1"}, "k2": {"v2_2", "v2_1"}, "k3": {"v3_1", "v3_2"}}, "k1=v1&k2=v2_1&k2=v2_2&k3=v3_1&k3=v3_2"},
		{url.Values{"k1": {"v1"}, "k2": {"v2_2", "v2_1"}, "k3": {"v3_2", "v3_1"}}, "k1=v1&k2=v2_1&k2=v2_2&k3=v3_1&k3=v3_2"},
		{url.Values{"k": {"v4", "v3", "v2", "v1"}}, "k=v1&k=v2&k=v3&k=v4"},
	}
	for _, tt := range tests {
		if got := (query{tt.values}).Encode(); got != tt.encoded {
			t.Errorf(`Encode(%+v) = %q, want %q`, tt.values, got, tt.encoded)
		}
	}
}

func loggingErrorHandler(t *testing.T) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		t.Helper()
		t.Logf("Handle request for URL: %q, error: %v", r.URL, err)
		DefaultErrorHandler(w, r, err)
	}
}

type staticSignerSource struct{ s Signer }

func (s staticSignerSource) Signer(context.Context, string) (Signer, error) { return s.s, nil }

type staticVerifierSource struct{ v Verifier }

func (s staticVerifierSource) Verifier(context.Context, string) (Verifier, error) { return s.v, nil }

func TestTransportMiddleware(t *testing.T) {
	urls := []string{
		"", "?k1=v1", "?k1=v&k2=v", "?k1=v1&k1=v2&k2=v",
		"/", "/?k1=v1", "/?k1=v&k2=v", "/?k1=v1&k1=v2&k2=v",
		"/p", "/p?k1=v1", "/p?k1=v&k2=v", "/p?k1=v1&k1=v2&k2=v",
		"/p/h", "/p/h?k1=v", "/p/h?k1=v&k2=v", "/p/h?k1=v1&k1=v2&k2=v",
	}
	sigver, err := hmac.New([]byte(key), crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create HMAC: %v", err)
	}
	c := http.Client{Transport: NewTransport(staticSignerSource{sigver}, kid)}
	mw := Middleware(staticVerifierSource{sigver}, loggingErrorHandler(t))

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "test response body")
	})
	h = mw(h)

	s := httptest.NewServer(h)
	defer s.Close()

	for _, u := range urls {
		u, err := url.JoinPath(s.URL, u)
		if err != nil {
			t.Fatalf("JoinPath(%q, %q) failed: %v", s.URL, u, err)
		}
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", u, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Get(%q); code: %d, want %d", u, resp.StatusCode, http.StatusOK)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			t.Logf("Response body: %q", body)
		}
	}
}

func TestMiddleware(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}

	sigver, err := hmac.New([]byte(key), crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create HMAC: %v", err)
	}

	if err := Sign(sigver, time.Now(), req); err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	req.Header.Add(KidHeader, "kid")

	tests := []struct {
		name    string
		headerf func(h http.Header)
	}{
		{
			name:    "missing " + TimestampHeader,
			headerf: func(h http.Header) { h.Del(TimestampHeader) },
		},
		{
			name:    "missing " + KidHeader,
			headerf: func(h http.Header) { h.Del(KidHeader) },
		},
		{
			name:    "missing " + SignatureHeader,
			headerf: func(h http.Header) { h.Del(SignatureHeader) },
		},
		{
			name:    "invalid signature",
			headerf: func(h http.Header) { h.Set(SignatureHeader, h.Get(SignatureHeader)+"malformed") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := req.Clone(context.Background())
			tt.headerf(r.Header)
			w := httptest.NewRecorder()

			h := Middleware(staticVerifierSource{sigver}, loggingErrorHandler(t))(http.NotFoundHandler())
			h.ServeHTTP(w, r)

			//nolint:bodyclose // Returned body is a NopCloser.
			if c := w.Result().StatusCode; c != http.StatusUnauthorized {
				t.Errorf("Status = %d, want %d", c, http.StatusUnauthorized)
			}
		})
	}
}
