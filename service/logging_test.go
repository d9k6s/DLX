package service

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRedactSensitiveQuery(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "token query",
			path: "/v1/translate?token=local-api-secret&source=en",
			want: "/v1/translate?source=en&token=REDACTED",
		},
		{
			name: "case insensitive token query",
			path: "/v1/translate?Token=local-api-secret",
			want: "/v1/translate?Token=REDACTED",
		},
		{
			name: "malformed query",
			path: "/v1/translate?token=%zz",
			want: "/v1/translate?[REDACTED]",
		},
		{
			name: "path without query",
			path: "/v1/translate",
			want: "/v1/translate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := redactSensitiveQuery(test.path); got != test.want {
				t.Fatalf("redacted path = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSafeGinLogFormatterDoesNotExposeQueryToken(t *testing.T) {
	secret := "local-api-secret"
	line := safeGinLogFormatter(gin.LogFormatterParams{
		TimeStamp:  time.Unix(1_800_000_000, 0),
		StatusCode: 200,
		Latency:    time.Millisecond,
		ClientIP:   "192.0.2.10",
		Method:     "POST",
		Path:       "/v1/translate?token=" + secret,
	})

	if strings.Contains(line, secret) {
		t.Fatalf("request log contains query token: %s", line)
	}
	if !strings.Contains(line, "/v1/translate?token=REDACTED") {
		t.Fatalf("request log does not contain redaction marker: %s", line)
	}
}
