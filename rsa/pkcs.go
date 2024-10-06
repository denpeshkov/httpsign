package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
)

// PKCSSigner signs messages using RSA-PKCS #1 v1.5.
// It is safe for concurrent use by multiple goroutines.
type PKCSSigner struct {
	PKCSVerifier
	Rand io.Reader // Defaults to crypto/rand.Reader if not set.

	priv *rsa.PrivateKey
}

// NewPKCSSigner returns a new [PKCSSigner] for the provided private key and hash algorithm.
func NewPKCSSigner(priv *rsa.PrivateKey, hash crypto.Hash) (*PKCSSigner, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &PKCSSigner{
		Rand:         rand.Reader,
		priv:         priv,
		PKCSVerifier: PKCSVerifier{pub: &priv.PublicKey, hash: hash},
	}, nil
}

// Sign signs a message using the private key.
func (s *PKCSSigner) Sign(message []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(s.Rand, s.priv, s.hash, s.digest(message))
}

// PKCSVerifier verifies RSA-PKCS #1 v1.5 message signatures.
// It is safe for concurrent use by multiple goroutines.
type PKCSVerifier struct {
	pub  *rsa.PublicKey
	hash crypto.Hash
}

// NewPKCSVerifier returns a new [PKCSVerifier] for the provided public key and hash algorithm.
func NewPKCSVerifier(pub *rsa.PublicKey, hash crypto.Hash) (*PKCSVerifier, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &PKCSVerifier{pub: pub, hash: hash}, nil
}

// Verify verifies the signature of a message using the public key.
func (v *PKCSVerifier) Verify(message []byte, signature []byte) (bool, error) {
	if err := rsa.VerifyPKCS1v15(v.pub, v.hash, v.digest(message), signature); err != nil {
		return false, err
	}
	return true, nil
}

func (v *PKCSVerifier) digest(msg []byte) []byte {
	h := v.hash.HashFunc().New()
	_, _ = h.Write(msg) // never returns an error
	return h.Sum(nil)
}
