package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/corinthian/traktctl/internal/config"
)

func TestOauthClientBodyOmitsEmptySecret(t *testing.T) {
	got := oauthClientBody(&config.Config{ClientID: "cid"}, map[string]string{"grant_type": "refresh_token"})
	if _, ok := got["client_secret"]; ok {
		t.Fatal("public client must not send client_secret key")
	}
	if got["client_id"] != "cid" || got["grant_type"] != "refresh_token" {
		t.Fatalf("unexpected body: %#v", got)
	}
}

func TestOauthClientBodyIncludesSecretWhenSet(t *testing.T) {
	got := oauthClientBody(&config.Config{ClientID: "cid", ClientSecret: "sec"}, map[string]string{})
	if got["client_secret"] != "sec" {
		t.Fatalf("confidential client body = %#v", got)
	}
}

func TestRefreshPublicClientNoSecretInBody(t *testing.T) {
	var body atomic.Value
	srv := oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		body.Store(m)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"new","refresh_token":"rt","token_type":"bearer","expires_in":604800,"created_at":1}`))
	})
	m := newTestManager(t, srv.URL)
	m.cfg.ClientSecret = ""
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := body.Load().(map[string]string)
	if _, ok := got["client_secret"]; ok {
		t.Fatalf("refresh sent client_secret: %#v", got)
	}
	if _, ok := got["redirect_uri"]; ok {
		t.Fatalf("public refresh must not send redirect_uri: %#v", got)
	}
}

func TestDeviceCodePublicClientSendsPKCEChallenge(t *testing.T) {
	var body atomic.Value
	srv := oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/device/code" {
			http.NotFound(w, r)
			return
		}
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		body.Store(m)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"device_code":"d","user_code":"ABCD1234","verification_url":"https://trakt.tv/activate","expires_in":600,"interval":5}`))
	})
	m := &Manager{
		cfg:   &config.Config{ClientID: "cid", BaseURL: srv.URL, Timeout: 5},
		store: &store{filePath: t.TempDir() + "/tokens.json"},
		http:  srv.Client(),
		errW:  io.Discard,
	}
	_, verifier, err := m.requestDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if verifier == "" {
		t.Fatal("expected a PKCE verifier for public client")
	}
	got := body.Load().(map[string]string)
	if got["code_challenge_method"] != "S256" {
		t.Fatalf("device/code body = %#v", got)
	}
	if got["code_challenge"] == "" {
		t.Fatal("missing code_challenge")
	}
	if _, ok := got["client_secret"]; ok {
		t.Fatal("must not send client_secret on device/code")
	}
}

func TestDeviceTokenPollSendsVerifierNotSecret(t *testing.T) {
	var pollBody atomic.Value
	srv := oauthServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"device_code":"dev","user_code":"U","verification_url":"https://trakt.tv/activate","expires_in":1,"interval":1}`))
		case "/oauth/device/token":
			var m map[string]string
			_ = json.NewDecoder(r.Body).Decode(&m)
			pollBody.Store(m)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"at","refresh_token":"rt","token_type":"bearer","expires_in":604800,"created_at":1}`))
		default:
			http.NotFound(w, r)
		}
	})
	m := &Manager{
		cfg:   &config.Config{ClientID: "cid", BaseURL: srv.URL, Timeout: 5},
		store: &store{filePath: t.TempDir() + "/tokens.json"},
		http:  srv.Client(),
		errW:  io.Discard,
	}
	_, _, err := m.LoginDevice(context.Background(), io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	got := pollBody.Load().(map[string]string)
	if got["code_verifier"] == "" {
		t.Fatalf("poll body = %#v", got)
	}
	if _, ok := got["client_secret"]; ok {
		t.Fatalf("poll must not send client_secret: %#v", got)
	}
}