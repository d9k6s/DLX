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

func cacheTestClient(t *testing.T, profile ClientProfile) string {
	t.Helper()
	return cacheSpecificTestClient(t, profile, req.C().SetTimeout(5*time.Second))
}

func cacheSpecificTestClient(t *testing.T, profile ClientProfile, client *req.Client) string {
	t.Helper()
	key := t.Name()
	cacheKey := oneshotClientCacheKey(profile, key)
	oneshotClients.Store(cacheKey, client)
	t.Cleanup(func() { oneshotClients.Delete(cacheKey) })
	return key
}

func TestParseClientProfile(t *testing.T) {
	tests := []struct {
		input   string
		want    ClientProfile
		wantErr bool
	}{
		{input: "", want: ClientProfileIOS},
		{input: "ios", want: ClientProfileIOS},
		{input: " CHROME ", want: ClientProfileChrome},
		{input: "safari", wantErr: true},
	}

	for _, test := range tests {
		got, err := ParseClientProfile(test.input)
		if test.wantErr {
			if err == nil {
				t.Fatalf("ParseClientProfile(%q) unexpectedly succeeded", test.input)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("ParseClientProfile(%q) = %q, %v; want %q, nil", test.input, got, err, test.want)
		}
	}
}

func TestOneshotRequestUsesSelectedClientProfile(t *testing.T) {
	tests := []struct {
		profile        ClientProfile
		wantOS         string
		wantOSVersion  string
		wantAppVersion string
		wantAppBuild   string
	}{
		{
			profile:        ClientProfileIOS,
			wantOS:         "iOS",
			wantOSVersion:  iosOSVersion,
			wantAppVersion: iosAppVersion,
			wantAppBuild:   iosAppBuild,
		},
		{
			profile:        ClientProfileChrome,
			wantOS:         "brex_" + chromePlatform,
			wantOSVersion:  "brex_Chrome_" + chromeBrowserVersion,
			wantAppVersion: chromeExtensionVersion,
			wantAppBuild:   chromeAppBuild,
		},
	}

	for _, test := range tests {
		t.Run(string(test.profile), func(t *testing.T) {
			request, err := newOneshotRequest(test.profile, "hello", "de", "en")
			if err != nil {
				t.Fatalf("newOneshotRequest() error = %v", err)
			}
			if request.AppInformation.OS != test.wantOS ||
				request.AppInformation.OSVersion != test.wantOSVersion ||
				request.AppInformation.AppVersion != test.wantAppVersion ||
				request.AppInformation.AppBuild != test.wantAppBuild {
				t.Fatalf("app_information = %#v", request.AppInformation)
			}
			if request.AppInformation.InstanceID != instanceID {
				t.Fatalf("instance_id = %q, want process instance %q", request.AppInformation.InstanceID, instanceID)
			}
		})
	}
}

func TestChromeClientUsesExtensionFetchHeaders(t *testing.T) {
	client, err := newOneshotClient(ClientProfileChrome, "")
	if err != nil {
		t.Fatalf("newOneshotClient() error = %v", err)
	}

	wantHeaders := map[string]string{
		"User-Agent":         chromeUserAgent(),
		"Origin":             chromeExtensionOrigin,
		"Sec-Fetch-Site":     "cross-site",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Dest":     "empty",
		"Sec-CH-UA-Platform": `"` + chromePlatform + `"`,
	}
	for name, want := range wantHeaders {
		if got := client.Headers.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Upgrade-Insecure-Requests", "Pragma", "Cache-Control"} {
		if got := client.Headers.Get(name); got != "" {
			t.Errorf("navigation-only %s unexpectedly retained as %q", name, got)
		}
	}
	if _, err := client.GetCookies("https://oneshot-free.www.deepl.com"); err == nil {
		t.Error("Chrome profile unexpectedly retained a cookie jar")
	}
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
	clientKey := cacheTestClient(t, ClientProfileIOS)
	done := make(chan error, 1)
	go func() {
		_, _, err := callOneshot(ctx, server.URL, []byte(`{}`), "", clientKey, ClientProfileIOS)
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

	_, _, err := callOneshot(context.Background(), server.URL, []byte(`{}`), "", cacheTestClient(t, ClientProfileIOS), ClientProfileIOS)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("callOneshot error = %v, want response size error", err)
	}
}

func TestCallOneshotOnlySendsIOSAppHeadersForIOSProfile(t *testing.T) {
	tests := []struct {
		profile ClientProfile
		wantIOS bool
	}{
		{profile: ClientProfileIOS, wantIOS: true},
		{profile: ClientProfileChrome, wantIOS: false},
	}

	for _, test := range tests {
		t.Run(string(test.profile), func(t *testing.T) {
			requestHeaders := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestHeaders <- r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			proxyKey := cacheTestClient(t, test.profile)
			_, _, err := callOneshot(context.Background(), server.URL, []byte(`{}`), "access-token", proxyKey, test.profile)
			if err != nil {
				t.Fatalf("callOneshot() error = %v", err)
			}
			headers := <-requestHeaders
			if got := headers.Get("Authorization"); got != "Bearer access-token" {
				t.Errorf("Authorization = %q", got)
			}
			for _, name := range []string{"x-app-os-version", "x-app-instance-id", "x-app-session-id"} {
				got := headers.Get(name)
				if test.wantIOS && got == "" {
					t.Errorf("%s is missing for iOS profile", name)
				}
				if !test.wantIOS && got != "" {
					t.Errorf("%s = %q for Chrome profile", name, got)
				}
			}
		})
	}
}

func TestChromeCallOneshotUsesExtensionFetchProfileWithoutCookies(t *testing.T) {
	client, err := newOneshotClient(ClientProfileChrome, "")
	if err != nil {
		t.Fatalf("newOneshotClient() error = %v", err)
	}

	requestHeaders := make(chan http.Header, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHeaders <- r.Header.Clone()
		http.SetCookie(w, &http.Cookie{Name: "upstream", Value: "should-not-return"})
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	proxyKey := cacheSpecificTestClient(t, ClientProfileChrome, client)
	for range 2 {
		_, _, err := callOneshot(context.Background(), server.URL, []byte(`{}`), "", proxyKey, ClientProfileChrome)
		if err != nil {
			t.Fatalf("callOneshot() error = %v", err)
		}
	}

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		headers := <-requestHeaders
		if got := headers.Get("User-Agent"); got != chromeUserAgent() {
			t.Errorf("request %d User-Agent = %q", requestNumber, got)
		}
		if got := headers.Get("Origin"); got != chromeExtensionOrigin {
			t.Errorf("request %d Origin = %q", requestNumber, got)
		}
		if got := headers.Get("Cookie"); got != "" {
			t.Errorf("request %d Cookie = %q", requestNumber, got)
		}
		for _, name := range []string{"x-app-os-version", "x-app-instance-id", "x-app-session-id"} {
			if got := headers.Get(name); got != "" {
				t.Errorf("request %d %s = %q", requestNumber, name, got)
			}
		}
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
