package service

import (
	"net/http/httptest"
	"testing"
)

func TestHasProAccessToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "missing token", token: "", want: false},
		{name: "opaque token", token: "opaque-access-token", want: true},
		{name: "JWT access token", token: "header.payload.signature", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasProAccessToken(tt.token); got != tt.want {
				t.Fatalf("hasProAccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "bearer", header: "Bearer local-token", want: "local-token"},
		{name: "case insensitive scheme", header: "bearer local-token", want: "local-token"},
		{name: "DeepL scheme", header: "DeepL-Auth-Key local-token", want: "local-token"},
		{name: "flexible whitespace", header: "  Bearer\tlocal-token  ", want: "local-token"},
		{name: "unsupported scheme", header: "Basic local-token", want: ""},
		{name: "missing token", header: "Bearer", want: ""},
		{name: "extra field", header: "Bearer local-token extra", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := authorizationToken(test.header); got != test.want {
				t.Fatalf("authorizationToken() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProAccessTokenFromCookieSelectsNamedCookie(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/translate", nil)
	req.Header.Set("Cookie", "theme=dark; dl_session=oauth-access-token; locale=zh-TW")

	if got := proAccessTokenFromCookie(req); got != "oauth-access-token" {
		t.Fatalf("proAccessTokenFromCookie() = %q, want oauth-access-token", got)
	}
}

func TestProAccessTokenFromCookieIgnoresOtherCookies(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/translate", nil)
	req.Header.Set("Cookie", "theme=dark; locale=zh-TW")

	if got := proAccessTokenFromCookie(req); got != "" {
		t.Fatalf("proAccessTokenFromCookie() = %q, want empty", got)
	}
}
