package httpsign

// Signer signs messages.
// It must be safe for concurrent use by multiple goroutines.
type Signer interface {
	Sign(message []byte) ([]byte, error)
}

// Verifier verifies message signatures.
// It must be safe for concurrent use by multiple goroutines.
type Verifier interface {
	Verify(message []byte, signature []byte) (bool, error)
}
