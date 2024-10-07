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

The API is based on two interfaces: `Signer` and `Verifier`.
`Signer` is essentially a wrapper around the signature algorithm's private key.
Because the private key also contains the corresponding public key, `Signer` can be used for verification as well.

`Verifier` uses the public key for verification. It is useful in situations where the user only has access to the public key and not the private key.

The HMAC algorithm is an exception, as it uses the same shared secret key for both signing and verification.
Therefore, the API provides a single structure, [`HMAC`](https://pkg.go.dev/github.com/denpeshkov/httpsign/hmac#HMAC), for both signing and verification.

# Usage

Here is an example using `HMAC-SHA-256` algorithm:

```go
sharedKey := []byte("shared-secret")

// Create the Signer using the shared secret key.
sgn, err := hshmac.New(sharedKey, crypto.SHA256)
if err != nil {
	log.Fatal(err)
}

// Create the Transport.
tr := httpsign.NewTransport(sgn)

// Create an HTTP client using our transport to sign outgoing requests.
c := &http.Client{Transport: tr}

// Create the Middleware to verify incoming requests signatures.
m := httpsign.NewMiddleware(sgn)

// Wrap the handler.
var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello")
})
handler = m.Handler(handler)

http.Handle("/api/foo", handler)
```

Here is an example using `RSASSA-PKCS1-v1.5 SHA-256` algorithm:

```go
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
hash := crypto.SHA256

// Create the Signer using the private key.
sgn, err := hsrsa.NewPKCSSigner(privateKey, hash)
if err != nil {
	log.Fatal(err)
}

// Create the Transport.
tr := httpsign.NewTransport(sgn)

// Create an HTTP client using our transport to sign outgoing requests.
c := &http.Client{Transport: tr}

// Create the Middleware to verify incoming requests signatures.
m := httpsign.NewMiddleware(sgn)

// Alternatively, we can explicitly create a Verifier using the public key.
vrf, err := hsrsa.NewPKCSVerifier(&privateKey.PublicKey, hash)
if err != nil {
	log.Fatal(err)
}
m = httpsign.NewMiddleware(vrf)

// Wrap the handler.
var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello")
})
handler = m.Handler(handler)

http.Handle("/api/foo", handler)
```