package hmac

import (
	"crypto"
	_ "crypto/sha256"
	"testing"
)

func TestSignVerify(t *testing.T) {
	key := []byte("secret")
	sig, err := New(key, crypto.SHA256)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	msg := []byte("test")

	testf := func() {
		for i := range 3 {
			t.Logf("Iteration %d", i)
			sign, err := sig.Sign(msg)
			if err != nil {
				t.Fatalf("Sign(%s) error: %v", msg, err)
			}
			if ok, err := sig.Verify(msg, sign); err != nil {
				t.Fatalf("Verify(%s, %x) error: %v", msg, sign, err)
			} else if !ok {
				t.Errorf("Signed message not verified")
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
