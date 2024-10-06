// Package ecdsa provides utilities for signing and verifying messages using ECDSA.
package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"
)

// ErrHashUnavailable is returned when the hash function is not linked into the binary.
var ErrHashUnavailable = errors.New("ecdsa: requested hash function is unavailable")

// Signer signs messages using ECDSA.
// It is safe for concurrent use by multiple goroutines.
type Signer struct {
	Verifier
	Rand io.Reader // Defaults to crypto/rand.Reader if not set.

	priv *ecdsa.PrivateKey
}

// NewSigner returns a new [Signer] for the provided private key and hash algorithm.
func NewSigner(priv *ecdsa.PrivateKey, hash crypto.Hash) (*Signer, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &Signer{
		Rand:     rand.Reader,
		priv:     priv,
		Verifier: Verifier{pub: &priv.PublicKey, hash: hash},
	}, nil
}

// Sign signs a message using the private key.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	return ecdsa.SignASN1(s.Rand, s.priv, s.digest(message))
}

// Verifier verifies ECDSA message signatures.
// It is safe for concurrent use by multiple goroutines.
type Verifier struct {
	pub  *ecdsa.PublicKey
	hash crypto.Hash
}

// NewVerifier returns a new [Verifier] for the provided public key and hash algorithm.
func NewVerifier(pub *ecdsa.PublicKey, hash crypto.Hash) (*Verifier, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &Verifier{pub: pub, hash: hash}, nil
}

// Verify verifies the signature of a message using the public key.
func (v *Verifier) Verify(message []byte, signature []byte) (bool, error) {
	return ecdsa.VerifyASN1(v.pub, v.digest(message), signature), nil
}

func (v *Verifier) digest(msg []byte) []byte {
	h := v.hash.New()
	_, _ = h.Write(msg) // never returns an error
	return h.Sum(nil)
}
