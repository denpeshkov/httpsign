package httpsign

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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

type stubSigner struct{}

func (stubSigner) Sign(message []byte) ([]byte, error) {
	return message, nil
}

type stubVerifier struct{}

func (stubVerifier) Verify(message []byte, signature []byte) (bool, error) {
	return string(message) == string(signature), nil
}

func TestHTTP(t *testing.T) {
	urls := []string{
		"", "?k1=v1", "?k1=v&k2=v", "?k1=v1&k1=v2&k2=v",
		"/", "/?k1=v1", "/?k1=v&k2=v", "/?k1=v1&k1=v2&k2=v",
		"/p", "/p?k1=v1", "/p?k1=v&k2=v", "/p?k1=v1&k1=v2&k2=v",
		"/p/h", "/p/h?k1=v", "/p/h?k1=v&k2=v", "/p/h?k1=v1&k1=v2&k2=v",
	}
	c := http.Client{Transport: NewTransport(stubSigner{})}
	m := NewMiddleware(stubVerifier{})
	m.ErrorHandler = loggingErrorHandler(t)

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "test response body")
	})
	h = m.Handler(h)

	s := httptest.NewServer(h)
	defer s.Close()

	for _, u := range urls {
		u, err := url.JoinPath(s.URL, u)
		if err != nil {
			t.Fatalf("JoinPath(%q, %q) error: %v", s.URL, u, err)
		}
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("Get(%s) error: %v", u, err)
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
