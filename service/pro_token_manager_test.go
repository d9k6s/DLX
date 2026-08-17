package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testJWT(expiresAt time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": expiresAt.Unix()})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func writeTokenResponse(t *testing.T, w http.ResponseWriter, accessToken, refreshToken, idToken string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"expires_in":    1200,
	}); err != nil {
		t.Errorf("encode token response: %v", err)
	}
}

func TestProTokenManagerKeepsStaticAccessTokenCompatibility(t *testing.T) {
	m, err := newProTokenManager(&Config{DlSession: "static-access-token"})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	got, err := m.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if got != "static-access-token" {
		t.Fatalf("access token = %q, want static token", got)
	}
}

func TestProTokenManagerRefreshesAndPersistsRotatedTokens(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	newAccessToken := testJWT(now.Add(20 * time.Minute))
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse refresh form: %v", err)
		}
		want := url.Values{
			"client_id":     {deepLOAuthClientID},
			"grant_type":    {"refresh_token"},
			"refresh_token": {"refresh-old"},
		}
		if !reflect.DeepEqual(r.PostForm, want) {
			t.Errorf("refresh form = %v, want %v", r.PostForm, want)
		}
		writeTokenResponse(t, w, newAccessToken, "refresh-new", "id-new")
	}))
	defer server.Close()

	stateFile := filepath.Join(t.TempDir(), "oauth.json")
	m, err := newProTokenManager(&Config{
		DlSession:      testJWT(now.Add(20 * time.Minute)),
		DlRefreshToken: "refresh-old",
		DlTokenStore:   stateFile,
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.tokenEndpoint = server.URL
	m.now = func() time.Time { return now }

	got, err := m.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if got != newAccessToken {
		t.Fatalf("access token was not rotated")
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}

	info, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("stat token state: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("token state mode = %o, want 600", info.Mode().Perm())
	}

	reloaded, err := newProTokenManager(&Config{
		DlSession:      "stale-access-token",
		DlRefreshToken: "refresh-old",
		DlTokenStore:   stateFile,
	})
	if err != nil {
		t.Fatalf("reload token manager: %v", err)
	}
	reloaded.tokenEndpoint = server.URL
	reloaded.now = func() time.Time { return now }
	reloadedToken, err := reloaded.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("get reloaded access token: %v", err)
	}
	if reloadedToken != newAccessToken {
		t.Fatalf("reloaded access token did not come from persisted state")
	}
	if calls.Load() != 1 {
		t.Fatalf("reload unexpectedly refreshed token; calls = %d", calls.Load())
	}
}

func TestProTokenManagerCoalescesConcurrentRefresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	newAccessToken := testJWT(now.Add(20 * time.Minute))
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		writeTokenResponse(t, w, newAccessToken, "refresh-new", "id-new")
	}))
	defer server.Close()

	m, err := newProTokenManager(&Config{
		DlSession:      testJWT(now.Add(-time.Minute)),
		DlRefreshToken: "refresh-old",
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.tokenEndpoint = server.URL
	m.now = func() time.Time { return now }

	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := m.getAccessToken(context.Background())
			if err == nil && token != newAccessToken {
				err = fmt.Errorf("unexpected access token")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}
}

func TestRefreshAfterUnauthorizedDoesNotReplayRotatedRefreshToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rejectedToken := testJWT(now.Add(20 * time.Minute))
	newAccessToken := testJWT(now.Add(40 * time.Minute))
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeTokenResponse(t, w, newAccessToken, "refresh-new", "id-new")
	}))
	defer server.Close()

	m, err := newProTokenManager(&Config{
		DlSession:      rejectedToken,
		DlRefreshToken: "refresh-old",
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.tokenEndpoint = server.URL
	m.now = func() time.Time { return now }

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := m.refreshAfterUnauthorized(context.Background(), rejectedToken)
			if err == nil && token != newAccessToken {
				err = fmt.Errorf("unexpected access token")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}
}

func TestWriteProTokenStateReplacesExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.json")
	first := persistedProTokenState{AccessToken: "access-1", RefreshToken: "refresh-1"}
	second := persistedProTokenState{AccessToken: "access-2", RefreshToken: "refresh-2"}

	if err := writeProTokenState(path, first); err != nil {
		t.Fatalf("write first state: %v", err)
	}
	if err := writeProTokenState(path, second); err != nil {
		t.Fatalf("replace token state: %v", err)
	}
	got, err := readProTokenState(path)
	if err != nil {
		t.Fatalf("read replaced state: %v", err)
	}
	if got.AccessToken != second.AccessToken || got.RefreshToken != second.RefreshToken {
		t.Fatalf("state was not replaced: %+v", got)
	}
}
