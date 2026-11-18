package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewPKCEPair(t *testing.T) {
	verifier, challenge, err := newPKCEPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("verifier length %d, want 43-128 per Trakt PKCE guide", len(verifier))
	}
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, c := range verifier {
		if !strings.ContainsRune(unreserved, c) {
			t.Fatalf("verifier contains disallowed rune %q", c)
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge = %q, want S256 base64url %q", challenge, want)
	}
}
