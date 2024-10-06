package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"testing"
)

func TestSignVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	hash := crypto.SHA256
	sig, err := NewSigner(key, hash)
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	ver, err := NewVerifier(&key.PublicKey, hash)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	msg := []byte("test")

	testf := func() {
		for i := range 3 {
			t.Logf("Iteration %d", i)
			sign, err := sig.Sign(msg)
			if err != nil {
				t.Fatalf("Signer.Sign(%s) error: %v", msg, err)
			}
			if ok, err := sig.Verify(msg, sign); err != nil {
				t.Fatalf("Signer.Verify(%s, %x) error: %v", msg, sign, err)
			} else if !ok {
				t.Errorf("Signed message not verified by Signer")
			}

			if ok, err := ver.Verify(msg, sign); err != nil {
				t.Fatalf("Verifier.Verify(%s, %x) error: %v", msg, sign, err)
			} else if !ok {
				t.Errorf("Signed message not verified by Verifier")
			}
		}
	}

	// Test for concurrency safety using the -race flag.
	t.Run("g1", func(t *testing.T) {
		t.Parallel()
		testf()
	})
	t.Run("g2", func(t *testing.T) {
		t.Parallel()
		testf()
	})
}
