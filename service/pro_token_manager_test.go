package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func captureStandardLog(run func()) string {
	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	}()
	run()
	return output.String()
}

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

func TestProTokenManagerDiscoversTokenEndpoint(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	newAccessToken := testJWT(now.Add(20 * time.Minute))
	var discoveryCalls atomic.Int32
	var tokenCalls atomic.Int32
	var server *httptest.Server

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveryCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": server.URL + "/token",
			})
		case "/token":
			tokenCalls.Add(1)
			writeTokenResponse(t, w, newAccessToken, "refresh-new", "id-new")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	m, err := newProTokenManager(&Config{
		DlSession:      testJWT(now.Add(-time.Minute)),
		DlRefreshToken: "refresh-old",
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.client = server.Client()
	m.discoveryEndpoint = server.URL + "/.well-known/openid-configuration"
	m.now = func() time.Time { return now }

	got, err := m.getAccessToken(context.Background())
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if got != newAccessToken {
		t.Fatal("access token was not returned from the discovered endpoint")
	}
	if discoveryCalls.Load() != 1 || tokenCalls.Load() != 1 {
		t.Fatalf("calls = discovery:%d token:%d, want 1 each", discoveryCalls.Load(), tokenCalls.Load())
	}
}

func TestProTokenManagerRejectsInsecureDiscoveredTokenEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": "http://auth.example.invalid/token",
		})
	}))
	defer server.Close()

	m, err := newProTokenManager(&Config{
		DlSession:      "expired-access-token",
		DlRefreshToken: "refresh-token",
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.client = server.Client()
	m.discoveryEndpoint = server.URL

	if _, err := m.getAccessToken(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid token endpoint") {
		t.Fatalf("getAccessToken error = %v, want invalid token endpoint", err)
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

func TestProTokenManagerLogsRefreshLifecycleWithoutCredentials(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	oldAccessToken := testJWT(now.Add(20 * time.Minute))
	newAccessToken := testJWT(now.Add(40 * time.Minute))
	oldRefreshToken := "refresh-secret-old"
	newRefreshToken := "refresh-secret-new"
	idToken := "id-secret-new"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTokenResponse(t, w, newAccessToken, newRefreshToken, idToken)
	}))
	defer server.Close()

	stateFile := filepath.Join(t.TempDir(), "oauth.json")
	m, err := newProTokenManager(&Config{
		DlSession:      oldAccessToken,
		DlRefreshToken: oldRefreshToken,
		DlTokenStore:   stateFile,
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.tokenEndpoint = server.URL
	m.now = func() time.Time { return now }

	var refreshErr error
	logs := captureStandardLog(func() {
		m.logConfiguration()
		_, refreshErr = m.getAccessToken(context.Background())
	})
	if refreshErr != nil {
		t.Fatalf("getAccessToken: %v", refreshErr)
	}

	for _, want := range []string{
		"access token is configured",
		"refresh token is configured",
		"no usable persisted token state was loaded",
		"refresh started (reason=bootstrap)",
		"refresh succeeded (reason=bootstrap",
		"refresh_token_rotated=true",
		"persisted=true",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs do not contain %q:\n%s", want, logs)
		}
	}
	for _, secret := range []string{oldAccessToken, newAccessToken, oldRefreshToken, newRefreshToken, idToken} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain credential value %q", secret)
		}
	}
}

func TestProTokenManagerLogsSanitizedOAuthFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	refreshToken := "refresh-secret"
	errorDescription := "refresh-secret was rejected"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": errorDescription,
		})
	}))
	defer server.Close()

	m, err := newProTokenManager(&Config{
		DlSession:      testJWT(now.Add(-time.Minute)),
		DlRefreshToken: refreshToken,
	})
	if err != nil {
		t.Fatalf("newProTokenManager: %v", err)
	}
	m.tokenEndpoint = server.URL
	m.now = func() time.Time { return now }

	var refreshErr error
	logs := captureStandardLog(func() {
		_, refreshErr = m.getAccessToken(context.Background())
	})
	if refreshErr == nil {
		t.Fatal("getAccessToken unexpectedly succeeded")
	}
	for _, want := range []string{"reason=expiring", "status=400", "oauth_error=invalid_grant"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs do not contain %q:\n%s", want, logs)
		}
	}
	for _, secret := range []string{refreshToken, errorDescription} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain sensitive OAuth response content %q", secret)
		}
	}
}
