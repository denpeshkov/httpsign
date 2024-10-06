package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha512"
	"testing"
)

func TestSignVerify_PSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	opts := &rsa.PSSOptions{Hash: crypto.SHA512}
	sig, err := NewPSSSigner(key, opts)
	if err != nil {
		t.Fatalf("NewPSSSigner() error: %v", err)
	}
	ver, err := NewPSSVerifier(&key.PublicKey, opts)
	if err != nil {
		t.Fatalf("NewPSSVerifier() error: %v", err)
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

func TestSignVerify_PKCS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	opts := crypto.SHA512
	sig, err := NewPKCSSigner(key, opts)
	if err != nil {
		t.Fatalf("NewPKCSSigner() error: %v", err)
	}
	ver, err := NewPKCSVerifier(&key.PublicKey, opts)
	if err != nil {
		t.Fatalf("NewPKCSVerifier() error: %v", err)
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
