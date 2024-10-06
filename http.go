// Package httpsign provides utilities for signing and verifying HTTP requests.
package httpsign

import (
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
	signatureHeader = "X-Signature"
	timestampHeader = "X-Signature-Timestamp"
)

var (
	// ErrVerification represents a failure to verify a signature.
	ErrVerification = errors.New("signature verification error")
)

// Transport is an HTTP [http.RoundTripper] which signs outgoing HTTP requests.
type Transport struct {
	// Base is the base http.RoundTripper used to make HTTP requests.
	// By default, http.DefaultTransport is used.
	Base http.RoundTripper

	signer Signer
}

// NewTransport returns a new [Transport] given a [Signer].
func NewTransport(signer Signer) *Transport {
	return &Transport{
		Base:   http.DefaultTransport,
		signer: signer,
	}
}

// RoundTrip implements the [http.RoundTripper] interface, signing the request using provided [Signer].
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
	if err := t.sign(r); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	bodyClosed = true // r.Body is closed by the base RoundTripper.
	return t.Base.RoundTrip(r)
}

func (t *Transport) sign(r *http.Request) error {
	var (
		method    = r.Method
		host      = r.Host
		path      = r.URL.EscapedPath()
		query     = query{r.URL.Query()}.Encode()
		timestamp = time.Now().UTC().Format(time.RFC3339)
	)
	if path == "" {
		path = "/" // See https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3
	}
	data := fmt.Sprintf("%s%s%s%s%s", method, host, path, query, timestamp)
	sig, err := t.signer.Sign([]byte(data))
	if err != nil {
		return err
	}
	esig := base64.RawURLEncoding.EncodeToString(sig)
	r.Header.Add(timestampHeader, timestamp)
	r.Header.Add(signatureHeader, esig)
	return nil
}

// DefaultErrorHandler handles errors as follows:
//   - If the error is [ErrVerification], it sends a 401 Unauthorized response.
//   - For any other errors, it defaults to sending a 500 Internal Server Error response.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, ErrVerification):
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

type Middleware struct {
	// ErrorHandler is used to handle errors that occur during signature verification.
	// If not provided, DefaultErrorHandler is used.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	verifier Verifier
}

// NewMiddleware returns a new [Middleware] given a [Verifier].
func NewMiddleware(verifier Verifier) *Middleware {
	return &Middleware{
		ErrorHandler: DefaultErrorHandler,
		verifier:     verifier,
	}
}

// Handler returns a handler that serves requests with signature verification.
func (m *Middleware) Handler(h http.Handler) http.Handler {
	return m.handler(func(w http.ResponseWriter, r *http.Request) error {
		var (
			method    = r.Method
			host      = r.Host
			path      = r.URL.EscapedPath()
			query     = query{r.URL.Query()}.Encode()
			timestamp = r.Header.Get(timestampHeader)
		)
		msg := fmt.Sprintf("%s%s%s%s%s", method, host, path, query, timestamp)

		sig, err := base64.RawURLEncoding.DecodeString(r.Header.Get(signatureHeader))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrVerification, err)
		}

		valid, err := m.verifier.Verify([]byte(msg), sig)
		if err != nil {
			return err
		}
		if !valid {
			return ErrVerification
		}
		h.ServeHTTP(w, r)
		return nil
	})
}

func (m *Middleware) handler(h func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			m.ErrorHandler(w, r, err)
		}
	})
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
