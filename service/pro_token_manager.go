package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	deepLOAuthTokenEndpoint = "https://w.deepl.com/oidc/token"
	deepLOAuthClientID      = "chromeExtension"
	proTokenRefreshSkew     = time.Minute
	proTokenRefreshTimeout  = 15 * time.Second
	maxTokenResponseSize    = 1 << 20
)

var (
	errNoProCredentials = errors.New("no DeepL Pro OAuth credentials configured")
	errNoRefreshToken   = errors.New("no DeepL Pro OAuth refresh token configured")
)

type persistedProTokenState struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type proTokenManager struct {
	mu sync.Mutex

	client        *http.Client
	tokenEndpoint string
	clientID      string
	stateFile     string
	now           func() time.Time

	accessToken  string
	refreshToken string
	idToken      string
	expiresAt    time.Time
}

type tokenRefreshError struct {
	status int
	err    error
}

func (e *tokenRefreshError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("DeepL OAuth refresh failed with status %d", e.status)
	}
	return fmt.Sprintf("DeepL OAuth refresh failed: %v", e.err)
}

func (e *tokenRefreshError) Unwrap() error {
	return e.err
}

func newProTokenManager(cfg *Config) (*proTokenManager, error) {
	m := &proTokenManager{
		client: &http.Client{
			Timeout: proTokenRefreshTimeout,
		},
		tokenEndpoint: deepLOAuthTokenEndpoint,
		clientID:      deepLOAuthClientID,
		stateFile:     cfg.DlTokenStore,
		now:           time.Now,
		accessToken:   cfg.DlSession,
		refreshToken:  cfg.DlRefreshToken,
	}
	if expiresAt, ok := jwtExpiry(cfg.DlSession); ok {
		m.expiresAt = expiresAt
	}

	if m.stateFile == "" {
		return m, nil
	}

	state, err := readProTokenState(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if state.RefreshToken != "" {
		m.accessToken = state.AccessToken
		m.refreshToken = state.RefreshToken
		m.idToken = state.IDToken
		m.expiresAt = state.ExpiresAt
	}
	return m, nil
}

func (m *proTokenManager) canRefresh() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshToken != ""
}

func (m *proTokenManager) getAccessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.accessToken == "" && m.refreshToken == "" {
		return "", errNoProCredentials
	}
	if m.refreshToken == "" {
		return m.accessToken, nil
	}
	if m.accessToken != "" && !m.expiresAt.IsZero() && m.now().Add(proTokenRefreshSkew).Before(m.expiresAt) {
		return m.accessToken, nil
	}
	return m.refreshLocked(ctx)
}

// refreshAfterUnauthorized refreshes only if rejectedToken is still current.
// Concurrent callers that observed the same rejected token therefore share
// the first caller's rotated token instead of replaying the old refresh token.
func (m *proTokenManager) refreshAfterUnauthorized(ctx context.Context, rejectedToken string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.refreshToken == "" {
		return "", errNoRefreshToken
	}
	if m.accessToken != "" && m.accessToken != rejectedToken {
		return m.accessToken, nil
	}
	return m.refreshLocked(ctx)
}

func (m *proTokenManager) refreshLocked(ctx context.Context) (string, error) {
	form := url.Values{
		"client_id":     {m.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {m.refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &tokenRefreshError{err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", &tokenRefreshError{err: err}
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize))
	if err := decoder.Decode(&payload); err != nil {
		return "", &tokenRefreshError{status: resp.StatusCode, err: errors.New("invalid token response")}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", &tokenRefreshError{status: resp.StatusCode}
	}
	if payload.AccessToken == "" {
		return "", &tokenRefreshError{status: resp.StatusCode, err: errors.New("token response is missing access_token")}
	}

	expiresAt, ok := jwtExpiry(payload.AccessToken)
	if payload.ExpiresIn > 0 {
		expiresAt = m.now().Add(time.Duration(payload.ExpiresIn) * time.Second)
		ok = true
	}
	if !ok {
		return "", &tokenRefreshError{status: resp.StatusCode, err: errors.New("token response is missing expiry information")}
	}

	refreshToken := payload.RefreshToken
	if refreshToken == "" {
		refreshToken = m.refreshToken
	}
	idToken := payload.IDToken
	if idToken == "" {
		idToken = m.idToken
	}

	m.accessToken = payload.AccessToken
	m.refreshToken = refreshToken
	m.idToken = idToken
	m.expiresAt = expiresAt

	if m.stateFile != "" {
		state := persistedProTokenState{
			AccessToken:  m.accessToken,
			RefreshToken: m.refreshToken,
			IDToken:      m.idToken,
			ExpiresAt:    m.expiresAt,
		}
		if err := writeProTokenState(m.stateFile, state); err != nil {
			return "", fmt.Errorf("persist refreshed DeepL OAuth tokens: %w", err)
		}
	}

	return m.accessToken, nil
}

func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.ExpiresAt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.ExpiresAt, 0), true
}

func readProTokenState(path string) (persistedProTokenState, error) {
	f, err := os.Open(path)
	if err != nil {
		return persistedProTokenState{}, err
	}
	defer f.Close()

	var state persistedProTokenState
	if err := json.NewDecoder(io.LimitReader(f, maxTokenResponseSize)).Decode(&state); err != nil {
		return persistedProTokenState{}, fmt.Errorf("read DeepL OAuth token state: %w", err)
	}
	return state, nil
}

func writeProTokenState(path string, state persistedProTokenState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".deepl-oauth-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	encoder := json.NewEncoder(tmp)
	if err := encoder.Encode(state); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func proTokenFailure(err error) (int, string) {
	var refreshErr *tokenRefreshError
	if errors.As(err, &refreshErr) && (refreshErr.status == http.StatusBadRequest || refreshErr.status == http.StatusUnauthorized) {
		return http.StatusUnauthorized, "DeepL Pro authentication could not be refreshed"
	}
	return http.StatusServiceUnavailable, "DeepL Pro authentication refresh failed"
}
