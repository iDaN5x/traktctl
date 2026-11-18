// PKCE helpers follow https://developer.trakt.tv/docs/pkce (S256 only).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// newPKCEPair returns a code_verifier and its S256 code_challenge per Trakt's
// PKCE guide (verifier 43–128 chars; challenge is SHA-256 base64url, no pad).
func newPKCEPair() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	if l := len(verifier); l < 43 || l > 128 {
		return "", "", fmt.Errorf("PKCE verifier length %d out of range", l)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
