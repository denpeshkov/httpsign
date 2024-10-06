// Package rsa provides utilities for signing and verifying messages using RSA.
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
)

// ErrHashUnavailable is returned when the hash function is not linked into the binary.
var ErrHashUnavailable = errors.New("rsa: requested hash function is unavailable")

// PSSSigner signs messages using RSA-PSS.
// It is safe for concurrent use by multiple goroutines.
type PSSSigner struct {
	PSSVerifier
	Rand io.Reader // Defaults to crypto/rand.Reader if not set.

	priv *rsa.PrivateKey
}

// NewPSSSigner returns a new [PSSSigner] for the provided private key.
func NewPSSSigner(priv *rsa.PrivateKey, opts *rsa.PSSOptions) (*PSSSigner, error) {
	if !opts.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &PSSSigner{
		Rand:        rand.Reader,
		priv:        priv,
		PSSVerifier: PSSVerifier{pub: &priv.PublicKey, opts: opts},
	}, nil
}

// Sign signs a message using the private key.
func (s *PSSSigner) Sign(message []byte) ([]byte, error) {
	return rsa.SignPSS(s.Rand, s.priv, s.opts.Hash, s.digest(message), s.opts)
}

// PSSVerifier verifies RSA-PSS message signatures.
// It is safe for concurrent use by multiple goroutines.
type PSSVerifier struct {
	pub  *rsa.PublicKey
	opts *rsa.PSSOptions
}

// NewPSSVerifier returns a new [PSSVerifier] for the provided public key.
func NewPSSVerifier(pub *rsa.PublicKey, opts *rsa.PSSOptions) (*PSSVerifier, error) {
	if !opts.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &PSSVerifier{pub: pub, opts: opts}, nil
}

// Verify verifies the signature of a message using the public key.
func (v *PSSVerifier) Verify(message []byte, signature []byte) (bool, error) {
	if err := rsa.VerifyPSS(v.pub, v.opts.Hash, v.digest(message), signature, v.opts); err != nil {
		return false, err
	}
	return true, nil
}

func (v *PSSVerifier) digest(msg []byte) []byte {
	h := v.opts.Hash.New()
	_, _ = h.Write(msg) // never returns an error
	return h.Sum(nil)
}
