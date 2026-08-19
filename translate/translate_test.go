package translate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imroc/req/v3"
)

func cacheTestClient(t *testing.T) string {
	t.Helper()
	key := t.Name()
	oneshotClients.Store(key, req.C().SetTimeout(5*time.Second))
	t.Cleanup(func() { oneshotClients.Delete(key) })
	return key
}

func TestCallOneshotHonorsContextCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseHandler
	}))
	defer func() {
		close(releaseHandler)
		server.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	clientKey := cacheTestClient(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := callOneshot(ctx, server.URL, []byte(`{}`), "", clientKey)
		done <- err
	}()

	select {
	case <-requestStarted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("callOneshot error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("callOneshot did not stop after context cancellation")
	}
}

func TestCallOneshotRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxOneshotResponseSize+1)))
	}))
	defer server.Close()

	_, _, err := callOneshot(context.Background(), server.URL, []byte(`{}`), "", cacheTestClient(t))
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("callOneshot error = %v, want response size error", err)
	}
}

func TestValidateOneshotTextLengthUsesSeparateFreeAndProLimits(t *testing.T) {
	freeTooLong := strings.Repeat("a", maxFreeTextLength+1)
	if err := validateOneshotTextLength(freeTooLong, false); err == nil {
		t.Fatal("anonymous validation unexpectedly accepted text over 1,500 characters")
	}
	if err := validateOneshotTextLength(freeTooLong, true); err != nil {
		t.Fatalf("Pro validation rejected text above the anonymous limit: %v", err)
	}

	if err := validateOneshotTextLength(strings.Repeat("a", maxProTextLength), true); err != nil {
		t.Fatalf("Pro validation rejected the exact 300,000-unit limit: %v", err)
	}
	if err := validateOneshotTextLength(strings.Repeat("a", maxProTextLength+1), true); err == nil {
		t.Fatal("Pro validation unexpectedly accepted text above 300,000 units")
	}
}

func TestValidateOneshotTextLengthCountsUTF16CodeUnits(t *testing.T) {
	// A supplementary Unicode code point occupies two UTF-16 code units,
	// matching JavaScript String.length in DeepL's official extension.
	exactLimit := strings.Repeat("😀", maxProTextLength/2)
	if got := utf16CodeUnitCount(exactLimit); got != maxProTextLength {
		t.Fatalf("utf16CodeUnitCount() = %d, want %d", got, maxProTextLength)
	}
	if err := validateOneshotTextLength(exactLimit, true); err != nil {
		t.Fatalf("Pro validation rejected exact supplementary-character limit: %v", err)
	}
	if err := validateOneshotTextLength(exactLimit+"😀", true); err == nil {
		t.Fatal("Pro validation unexpectedly accepted supplementary text above the limit")
	}
}
