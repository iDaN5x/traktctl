package auth

import "testing"

func TestAllowedBrowserURL(t *testing.T) {
	tests := []struct {
		raw string
		ok  bool
	}{
		{"https://trakt.tv/activate", true},
		{"https://api.trakt.tv/oauth/device", true},
		{"https://evil.trakt.tv/activate", true},
		{"http://trakt.tv/activate", false},
		{"https://trakt.tv.evil.example/activate", false},
		{"https://evil.example/trakt.tv", false},
		{"https://user:pass@trakt.tv/activate", false},
		{"file:///etc/passwd", false},
		{"", false},
		{"not a url", false},
	}
	for _, tc := range tests {
		got := allowedBrowserURL(tc.raw)
		if got != tc.ok {
			t.Errorf("allowedBrowserURL(%q) = %v, want %v", tc.raw, got, tc.ok)
		}
	}
}