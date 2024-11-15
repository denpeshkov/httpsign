// Package httpsign provides utilities for signing and verifying HTTP requests.
package httpsign

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	SignatureHeader = "X-Signature"
	TimestampHeader = "X-Signature-Timestamp"
	KidHeader       = "X-Key-ID"
)

var (
	// ErrRequestVerification represents a failure to verify an HTTP request.
	ErrRequestVerification = errors.New("failed to verify HTTP request")
)

// Sign signs the HTTP request using the provided signer and timestamp.
func Sign(s Signer, timestamp time.Time, r *http.Request) error {
	var (
		method = r.Method
		host   = r.Host
		path   = r.URL.EscapedPath()
		query  = query{r.URL.Query()}.Encode()
		ts     = timestamp.UTC().Format(time.RFC3339)
	)
	if path == "" {
		path = "/" // See https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3
	}
	data := fmt.Sprintf("%s%s%s%s%s", method, host, path, query, ts)
	sig, err := s.Sign([]byte(data))
	if err != nil {
		return err
	}
	sige := base64.RawURLEncoding.EncodeToString(sig)
	r.Header.Add(TimestampHeader, ts)
	r.Header.Add(SignatureHeader, sige)
	return nil
}

// SignerSource provides a [Signer] given a key ID.
// It must be safe for concurrent use by multiple goroutines.
type SignerSource interface {
	Signer(ctx context.Context, kid string) (Signer, error)
}

// Transport is an [http.RoundTripper] which signs outgoing HTTP requests.
type Transport struct {
	// Base is the base http.RoundTripper used to make HTTP requests.
	// By default, http.DefaultTransport is used.
	Base http.RoundTripper

	source SignerSource
	kid    string
}

// NewTransport returns a new [Transport] using a [SignerSource] with the provided key ID.
func NewTransport(source SignerSource, kid string) *Transport {
	return &Transport{
		Base:   http.DefaultTransport,
		source: source,
		kid:    kid,
	}
}

// RoundTrip signs the request.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	bodyClosed := false
	if r.Body != nil {
		defer func() {
			if !bodyClosed {
				_ = r.Body.Close()
			}
		}()
	}

	r = r.Clone(r.Context()) // per RoundTripper contract.
	r.Header.Set(KidHeader, t.kid)
	signer, err := t.source.Signer(r.Context(), t.kid)
	if err != nil {
		return nil, fmt.Errorf("obtain signer: %w", err)
	}
	if err := Sign(signer, time.Now(), r); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	bodyClosed = true // r.Body is closed by the base RoundTripper.
	return t.Base.RoundTrip(r)
}

// Verify verifies the HTTP request using the provided verifier.
func Verify(v Verifier, r *http.Request) error {
	var (
		method    = r.Method
		host      = r.Host
		path      = r.URL.EscapedPath()
		query     = query{r.URL.Query()}.Encode()
		timestamp = r.Header.Get(TimestampHeader)
	)
	if timestamp == "" {
		return fmt.Errorf("missing %s header", TimestampHeader)
	}
	sigRaw := r.Header.Get(SignatureHeader)
	if sigRaw == "" {
		return fmt.Errorf("missing %s header", SignatureHeader)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigRaw)
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	msg := fmt.Sprintf("%s%s%s%s%s", method, host, path, query, timestamp)

	valid, err := v.Verify([]byte(msg), sig)
	if err != nil {
		return fmt.Errorf("verification failure: %w", err)
	}
	if !valid {
		return errors.New("invalid signature")
	}
	return nil
}

// VerifierSource provides a [Verifier] given a key ID.
// It must be safe for concurrent use by multiple goroutines.
type VerifierSource interface {
	Verifier(ctx context.Context, kid string) (Verifier, error)
}

// DefaultErrorHandler handles errors as follows:
//   - If the error is [ErrRequestVerification], it sends a 401 Unauthorized response.
//   - For any other errors, it defaults to sending a 500 Internal Server Error response.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, ErrRequestVerification):
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// Middleware creates middleware that verifies HTTP request signatures using a [Verifier]
// from the provided source and handles errors with a custom handler.
func Middleware(
	source VerifierSource,
	errHandler func(w http.ResponseWriter, r *http.Request, err error),
) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			kid := r.Header.Get(KidHeader)
			if kid == "" {
				errHandler(w, r, fmt.Errorf("%w: missing %s header", ErrRequestVerification, KidHeader))
				return
			}
			v, err := source.Verifier(r.Context(), kid)
			if err != nil {
				errHandler(w, r, fmt.Errorf("obtain verifier: %w", err))
				return
			}
			if err := Verify(v, r); err != nil {
				errHandler(w, r, fmt.Errorf("%w: %w", ErrRequestVerification, err))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// query embeds [url.Values] overriding [url.Values.Encode] to sort by both key and value.
type query struct{ url.Values }

// Encode encodes the query parameters into “URL encoded” form ("bar=baz&foo=quux") sorted by key and value.
func (q query) Encode() string {
	if len(q.Values) == 0 {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(q.Values))
	for k := range q.Values {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		values := q.Values[k]
		slices.Sort(values)
		keyEscaped := url.QueryEscape(k)
		for _, v := range values {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
		}
	}
	return buf.String()
}
