package service

import "testing"

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
