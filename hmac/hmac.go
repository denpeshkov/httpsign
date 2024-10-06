// Package hmac provides utilities for signing and verifying messages using HMAC.
package hmac

import (
	"crypto"
	"crypto/hmac"
	"errors"
)

// ErrHashUnavailable is returned when the hash function is not linked into the binary.
var ErrHashUnavailable = errors.New("hmac: requested hash function is unavailable")

// HMAC signs messages and verifies message signatures using HMAC.
// It is safe for concurrent use by multiple goroutines.
type HMAC struct {
	key  []byte
	hash crypto.Hash
}

// New returns a new [HMAC] for the provided key and hash algorithm.
func New(key []byte, hash crypto.Hash) (*HMAC, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable
	}
	return &HMAC{key: key, hash: hash}, nil
}

// Sign signs a message using the key.
func (h HMAC) Sign(message []byte) ([]byte, error) {
	return h.digest(message), nil
}

// Verify verifies the signature of a message using the key.
func (h HMAC) Verify(message []byte, signature []byte) (bool, error) {
	return hmac.Equal(signature, h.digest(message)), nil
}

func (h HMAC) digest(msg []byte) []byte {
	hash := hmac.New(h.hash.New, h.key)
	_, _ = hash.Write(msg) // never returns an error
	return hash.Sum(nil)
}
