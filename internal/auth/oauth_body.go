package auth

import "github.com/corinthian/traktctl/internal/config"

// oauthClientBody builds a JSON object for Trakt OAuth calls. client_id is
// always set. client_secret is included only when configured — public PKCE
// clients must not send an empty secret.
func oauthClientBody(cfg *config.Config, fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields)+2)
	for k, v := range fields {
		out[k] = v
	}
	out["client_id"] = cfg.ClientID
	if cfg.ClientSecret != "" {
		out["client_secret"] = cfg.ClientSecret
	}
	return out
}
