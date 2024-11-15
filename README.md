# httpsign

[![CI](https://github.com/denpeshkov/httpsign/actions/workflows/ci.yml/badge.svg)](https://github.com/denpeshkov/httpsign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/denpeshkov/httpsign.svg)](https://pkg.go.dev/github.com/denpeshkov/httpsign)

`httpsign` provides utilities for creating, encoding, and verifying signatures within HTTP requests. Library provides both the transport to create digital signatures or message authentication codes (MACs), and a middleware to verify such signatures.

# Overview

The library provides the following signature algorithms:

- [HMAC](https://pkg.go.dev/github.com/denpeshkov/httpsign/hmac)
- [RSA](https://pkg.go.dev/github.com/denpeshkov/httpsign/rsa)
- [ECDSA](https://pkg.go.dev/github.com/denpeshkov/httpsign/ecdsa)
- [Ed25519](https://pkg.go.dev/github.com/denpeshkov/httpsign/ed25519)

The API is based on four interfaces: `Signer`, `Verifier` and `SignerSource`, `VerifierSource`.

`Signer` is essentially a wrapper around the signature algorithm's private key.
Because the private key also contains the corresponding public key, `Signer` can be used for verification as well.
`SignerSource` abstracts the retrieval of `Signer` based on the provided key ID.

`Verifier` uses the public key for verification. It is useful in situations where the user only has access to the public key and not the private key.
`VerifierSource` abstracts the retrieval of `Verifier` based on the provided key ID.

The HMAC algorithm is an exception, as it uses the same shared secret key for both signing and verification.
Therefore, the API provides a single structure, [`HMAC`](https://pkg.go.dev/github.com/denpeshkov/httpsign/hmac#HMAC), for both signing and verification.

# Usage

Here is an example using `HMAC-SHA-256` algorithm:

```go
type staticSource struct{ h *hmac.HMAC }

func (s staticSource) Signer(ctx context.Context, kid string) (Signer, error) {
	return s.h, nil
}
func (s staticSource) Verifier(ctx context.Context, kid string) (Verifier, error) {
	return s.h, nil
}

const (
	secret = "shared-secret"
	kid    = "key-id"
)

// Create the signer using the shared secret key.
sgn, err := hmac.New([]byte(secret), crypto.SHA256)
if err != nil {
	log.Fatal(err)
}

// Create the source given the signer.
src := staticSource{sgn}

// Create the Transport.
tr := NewTransport(src, kid)

// Create an HTTP client using our transport to sign outgoing requests.
c := &http.Client{Transport: tr}

// Create the Middleware to verify incoming requests signatures.
m := Middleware(src, DefaultErrorHandler)

// Wrap the handler.
var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello")
})
handler = m(handler)

http.Handle("/api/foo", handler)
```

Here is an example using `RSASSA-PKCS1-v1.5 SHA-256` algorithm:

```go
type staticSource struct{ h *rsa.PKCSSigner }

func (s staticSource) Signer(ctx context.Context, kid string) (Signer, error) {
	return s.h, nil
}
func (s staticSource) Verifier(ctx context.Context, kid string) (Verifier, error) {
	return s.h, nil
}

const kid = "key-id"

privateKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
hash := crypto.SHA256

// Create the signer using the shared secret key.
sgn, err := rsa.NewPKCSSigner(privateKey, hash)
if err != nil {
	log.Fatal(err)
}

// Create the source given the signer.
src := staticSource{sgn}

// Create the Transport.
tr := NewTransport(src, kid)

// Create an HTTP client using our transport to sign outgoing requests.
c := &http.Client{Transport: tr}

// Create the Middleware to verify incoming requests signatures.
m := Middleware(src, DefaultErrorHandler)

// Alternatively, we can explicitly create a Verifier using the public key.
vrf, err := hsrsa.NewPKCSVerifier(&privateKey.PublicKey, hash)
if err != nil {
	log.Fatal(err)
}

// Wrap the handler.
var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello")
})
handler = m(handler)

http.Handle("/api/foo", handler)
```