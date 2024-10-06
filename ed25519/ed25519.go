// Package ed25519 provides utilities for signing and verifying messages using Ed25519.
package ed25519

import (
	"crypto/ed25519"
	"errors"
)

var ErrInvalidKey = errors.New("ed25519: bad key length")

// Signer signs messages using Ed25519.
// It is safe for concurrent use by multiple goroutines.
type Signer struct {
	Verifier

	priv ed25519.PrivateKey
}

// NewSigner returns a new [Signer] for the provided private key and hash algorithm.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return &Signer{
		priv:     priv,
		Verifier: Verifier{pub: priv.Public().(ed25519.PublicKey)},
	}, nil
}

// Sign signs a message using the private key.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// Verifier verifies Ed25519 message signatures.
// It is safe for concurrent use by multiple goroutines.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier returns a new [Verifier] for the provided public key and hash algorithm.
func NewVerifier(pub ed25519.PublicKey) (*Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return &Verifier{pub: pub}, nil
}

// Verify verifies the signature of a message using the public key.
func (v *Verifier) Verify(message []byte, signature []byte) (bool, error) {
	return ed25519.Verify(v.pub, message, signature), nil
}
