package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	deepLOAuthDiscoveryEndpoint = "https://auth.deepl.com/.well-known/openid-configuration"
	deepLOAuthClientID          = "chromeExtension"
	proTokenRefreshSkew         = time.Minute
	proTokenRefreshTimeout      = 15 * time.Second
	maxTokenResponseSize        = 1 << 20
)

type proTokenRefreshReason string

const (
	proTokenRefreshBootstrap    proTokenRefreshReason = "bootstrap"
	proTokenRefreshExpiring     proTokenRefreshReason = "expiring"
	proTokenRefreshUnauthorized proTokenRefreshReason = "upstream_401"
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

	client            *http.Client
	discoveryEndpoint string
	tokenEndpoint     string
	clientID          string
	stateFile         string
	now               func() time.Time

	accessToken  string
	refreshToken string
	idToken      string
	expiresAt    time.Time
	stateLoaded  bool
}

type tokenRefreshError struct {
	status    int
	oauthCode string
	err       error
}

func (e *tokenRefreshError) Error() string {
	if e.status != 0 {
		if e.oauthCode != "" {
			return fmt.Sprintf("DeepL OAuth refresh failed with status %d (%s)", e.status, e.oauthCode)
		}
		return fmt.Sprintf("DeepL OAuth refresh failed with status %d", e.status)
	}
	return fmt.Sprintf("DeepL OAuth refresh failed: %v", e.err)
}

func (e *tokenRefreshError) Unwrap() error {
	return e.err
}

func newProTokenManager(cfg *Config) (*proTokenManager, error) {
	client, err := newProHTTPClient(cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("configure DeepL OAuth HTTP client: %w", err)
	}
	m := &proTokenManager{
		client:            client,
		discoveryEndpoint: deepLOAuthDiscoveryEndpoint,
		clientID:          deepLOAuthClientID,
		stateFile:         cfg.DlTokenStore,
		now:               time.Now,
		accessToken:       cfg.DlSession,
		refreshToken:      cfg.DlRefreshToken,
	}
	if expiresAt, ok := jwtExpiry(cfg.DlSession); ok {
		m.expiresAt = expiresAt
	}

	if m.stateFile == "" {
		return m, nil
	}

	state, err := readProTokenState(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		// Claim and persist the supplied refresh-token generation on the first
		// Pro request. Waiting for the access token to expire would leave the
		// browser extension and DLX racing to rotate the same refresh token.
		if m.refreshToken != "" {
			m.expiresAt = time.Time{}
		}
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
		m.stateLoaded = true
	}
	return m, nil
}

func newProHTTPClient(proxyURL string) (*http.Client, error) {
	var transport http.RoundTripper = http.DefaultTransport

	if proxyURL != "" {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("default HTTP transport has an unsupported type")
		}
		proxy, err := url.Parse(proxyURL)
		if err != nil || proxy.Scheme == "" || proxy.Host == "" {
			return nil, errors.New("invalid proxy URL")
		}
		proxyTransport := defaultTransport.Clone()
		proxyTransport.Proxy = http.ProxyURL(proxy)
		transport = proxyTransport
	}

	return &http.Client{
		Transport: transport,
		Timeout:   proTokenRefreshTimeout,
	}, nil
}

func (m *proTokenManager) logConfiguration() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.accessToken == "" {
		log.Println("[DeepL OAuth] access token is not configured.")
	} else {
		log.Printf("[DeepL OAuth] access token is configured (expires_at=%s).", formatTokenExpiry(m.expiresAt))
	}
	if m.refreshToken == "" {
		log.Println("[DeepL OAuth] refresh token is not configured; automatic refresh is disabled.")
		return
	}

	log.Println("[DeepL OAuth] refresh token is configured; automatic refresh is enabled.")
	switch {
	case m.stateFile == "":
		log.Println("[DeepL OAuth] token state persistence is disabled.")
	case m.stateLoaded:
		log.Printf("[DeepL OAuth] persisted token state was loaded (expires_at=%s).", formatTokenExpiry(m.expiresAt))
	default:
		log.Println("[DeepL OAuth] no usable persisted token state was loaded; the first Pro request will bootstrap it.")
	}
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
	reason := proTokenRefreshExpiring
	if m.expiresAt.IsZero() {
		reason = proTokenRefreshBootstrap
	}
	return m.refreshLocked(ctx, reason)
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
	return m.refreshLocked(ctx, proTokenRefreshUnauthorized)
}

func (m *proTokenManager) refreshLocked(ctx context.Context, reason proTokenRefreshReason) (token string, err error) {
	log.Printf("[DeepL OAuth] access token refresh started (reason=%s).", reason)
	defer func() {
		if err != nil {
			logTokenRefreshFailure(reason, err)
		}
	}()

	previousRefreshToken := m.refreshToken
	tokenEndpoint, err := m.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", fmt.Errorf("discover DeepL OAuth token endpoint: %w", err)
	}
	form := url.Values{
		"client_id":     {m.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {m.refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
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
		Error        string `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize))
	if err := decoder.Decode(&payload); err != nil {
		return "", &tokenRefreshError{status: resp.StatusCode, err: errors.New("invalid token response")}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", &tokenRefreshError{status: resp.StatusCode, oauthCode: safeOAuthErrorCode(payload.Error)}
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
		m.stateLoaded = true
	}

	log.Printf(
		"[DeepL OAuth] access token refresh succeeded (reason=%s, expires_at=%s, refresh_token_rotated=%t, persisted=%t).",
		reason,
		formatTokenExpiry(m.expiresAt),
		m.refreshToken != previousRefreshToken,
		m.stateFile != "",
	)
	return m.accessToken, nil
}

func (m *proTokenManager) resolveTokenEndpoint(ctx context.Context) (string, error) {
	if m.tokenEndpoint != "" {
		return m.tokenEndpoint, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.discoveryEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("OIDC discovery failed with status %d", resp.StatusCode)
	}

	var metadata struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize)).Decode(&metadata); err != nil {
		return "", errors.New("invalid OIDC discovery response")
	}
	endpointURL, err := url.Parse(metadata.TokenEndpoint)
	if err != nil || endpointURL.Scheme != "https" || endpointURL.Host == "" {
		return "", errors.New("OIDC discovery returned an invalid token endpoint")
	}

	m.tokenEndpoint = endpointURL.String()
	log.Printf("[DeepL OAuth] OIDC discovery resolved token endpoint (token_endpoint=%s).", m.tokenEndpoint)
	return m.tokenEndpoint, nil
}

func formatTokenExpiry(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "unknown"
	}
	return expiresAt.UTC().Format(time.RFC3339)
}

func safeOAuthErrorCode(code string) string {
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, char := range code {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' {
			continue
		}
		return ""
	}
	return code
}

func logTokenRefreshFailure(reason proTokenRefreshReason, err error) {
	var refreshErr *tokenRefreshError
	if errors.As(err, &refreshErr) && refreshErr.status != 0 {
		if refreshErr.oauthCode != "" {
			log.Printf("[DeepL OAuth] access token refresh failed (reason=%s, status=%d, oauth_error=%s).", reason, refreshErr.status, refreshErr.oauthCode)
			return
		}
		log.Printf("[DeepL OAuth] access token refresh failed (reason=%s, status=%d).", reason, refreshErr.status)
		return
	}
	log.Printf("[DeepL OAuth] access token refresh failed (reason=%s): %v", reason, err)
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
