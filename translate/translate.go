/*
 * @Author: Vincent Young
 * @Date: 2024-09-16 11:59:24
 * @LastEditors: Vincent Yang
 * @LastEditTime: 2026-08-04 00:00:00
 * @FilePath: /DLX/translate/translate.go
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 *
 * Copyright © 2024 by Vincent, All Rights Reserved.
 */

package translate

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

// DeepL's interactive clients (web, Chrome extension, and the official iOS
// app) all share the same stateless "oneshot" translate endpoint. The
// legacy LMT_handle_texts backend on www2.deepl.com rate-limits anonymous
// traffic hard; oneshot lives on a separate pool and accepts the literal
// header `Authorization: None` for free requests.
//
// Request profiles are reverse-engineered from DeepL iOS 26.42 and the
// official Chrome extension 1.97.0. Both use the same oneshot endpoint and
// JSON contract, but their transport, headers, cookies, and app_information
// identity must not be mixed.
//
//	Transport
//	  ItaClient oneshot uses Ktor Darwin engine
//	  (io.ktor.client.engine.darwin.KtorNSURLSessionDelegate) → real
//	  URLSession TLS. We approximate that ClientHello with utls HelloIOS.
//
//	Free URL   → https://oneshot-free.www.deepl.com/v1/translate
//	Pro URL    → https://oneshot. + <cell> + .pro.deepl.com/v1/translate
//	             (we keep oneshot-pro.www as the free-tier Pro fallback)
//
//	Headers (ClientInfos.appHeaders + LoginNone):
//	  Authorization: None          (ItaClient.LoginNone)
//	  x-app-os-version             (UIDevice.systemVersion)
//	  x-app-instance-id            (stable install UUID)
//	  x-app-session-id             (session UUID)
//	  User-Agent                   (URLSession / CFNetwork product form)
//	  Accept / Accept-Encoding     (URLSession defaults)
//
//	Body (ItaClient OneShotTranslationRequestDto + AppInformation):
//	  text[], target_lang, source_lang?, usage_type, app_information
//	  usage_type ∈ {translate, ocr, voiceforconversations}
//
// DeepL rate-limits / temporarily bans clients whose TLS + UA + app_information
// story is inconsistent. Keep every field on one coherent client profile.
type ClientProfile string

const (
	ClientProfileIOS    ClientProfile = "ios"
	ClientProfileChrome ClientProfile = "chrome"

	oneshotFreeEndpoint = "https://oneshot-free.www.deepl.com/v1/translate"
	oneshotProEndpoint  = "https://oneshot-pro.www.deepl.com/v1/translate"

	// Pinned to DeepL iOS IPA (CFBundleShortVersionString / CFBundleVersion).
	iosAppVersion = "26.42"
	iosAppBuild   = "5443737"

	// Reported OS version for app_information.os_version + x-app-os-version.
	// IPA is built against iphoneos26.5 (DTPlatformVersion). Must be a real
	// shipping major — a future value (e.g. 27.0) combined with an iOS TLS
	// fingerprint is rejected with HTTP 429 and can temp-ban the IP.
	iosOSVersion = "26.0"

	// CFNetwork / Darwin versions that accompany URLSession User-Agents on
	// the same OS generation as DTPlatformVersion 26.x (build machine
	// BuildMachineOSBuild 25E246 → Darwin 25).
	iosCFNetworkVersion = "3826.600.41"
	iosDarwinVersion    = "25.0.0"

	// Chrome profile values are aligned with req/v3 v3.60.0's newest available
	// Chrome ClientHello (utls HelloChrome_Auto = Chrome 133). The extension
	// derives these fields from navigator and chrome.runtime at runtime.
	chromeExtensionVersion = "1.97.0"
	chromeBrowserMajor     = "133"
	chromeBrowserVersion   = "133.0.0.0"
	chromePlatform         = "macOS"
	chromeAppBuild         = "chrome_web_store"
	chromeExtensionOrigin  = "chrome-extension://cofdbpoegempjloogbagkncekinflcnj"

	// oneshot enforces a 1500-character hard cap on the total length of
	// the `text` array for anonymous traffic (same limit the Chrome
	// extension documents as G.notLoggedIn). Bail early to spare the
	// upstream and give the caller a faster error.
	maxFreeTextLength = 1500

	// DeepL Chrome extension 1.97.0 enforces this per-source-text limit
	// before calling the authenticated oneshot endpoint. JavaScript
	// String.length counts UTF-16 code units, so v1 uses the same measure.
	maxProTextLength = 300000

	// oneshotTimeout caps how long we wait on a single translate request.
	oneshotTimeout = 20 * time.Second

	// warmupTimeout caps the initial GET to www.deepl.com that seeds the
	// cookie jar. Cookies are best-effort; skip a slow warmup rather than
	// block the first translation.
	warmupTimeout = 5 * time.Second

	// maxOneshotResponseSize prevents a broken or hostile upstream/proxy
	// from making the process buffer an unbounded response in memory.
	maxOneshotResponseSize = 4 << 20
)

func ParseClientProfile(value string) (ClientProfile, error) {
	switch ClientProfile(strings.ToLower(strings.TrimSpace(value))) {
	case "", ClientProfileIOS:
		return ClientProfileIOS, nil
	case ClientProfileChrome:
		return ClientProfileChrome, nil
	default:
		return "", fmt.Errorf("unsupported DeepL client profile %q (supported: ios, chrome)", value)
	}
}

// instanceID mirrors the stable installation/browser instance ID used by both
// client profiles. It remains stable for the process lifetime and is reused on
// every request; rotating it per request is a stronger bot signal.
var instanceID = newInstanceID()

// sessionID is sent as x-app-session-id (ClientInfos.appHeaders). Stable
// for the process lifetime, independent of instanceID.
var sessionID = newInstanceID()

// A real iOS URLSession inherits whatever cookies the app has on
// .deepl.com. A cold visit to www.deepl.com sets userCountry=<iso2> and
// verifiedBot=false. Share a process-wide jar so every oneshot POST
// carries whatever the warmup GET picked up.
var (
	cookieJar     http.CookieJar
	cookieJarOnce sync.Once
	cookieWarmer  sync.Once
)

// oneshotClients caches one req.Client per profile and proxy URL so all
// compatible calls share the underlying TCP / TLS / HTTP/2 connection pool.
var oneshotClients sync.Map // map[string]*req.Client

func sharedCookieJar() http.CookieJar {
	cookieJarOnce.Do(func() {
		j, _ := cookiejar.New(nil)
		cookieJar = j
	})
	return cookieJar
}

// warmCookies primes the shared jar by GETting www.deepl.com once.
// The Set-Cookie response lands on .deepl.com (eTLD+1 of oneshot-free),
// so subsequent POSTs carry those cookies automatically.
func warmCookies(client *req.Client) {
	cookieWarmer.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), warmupTimeout)
		defer cancel()
		_, _ = client.R().SetContext(ctx).Get("https://www.deepl.com/translator")
	})
}

func newInstanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // RFC 4122 v4
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

// Language code tables mirror ItaClient.OutputLanguage / InputLanguage
// (regional cases enUs, enGb, frCa, deCh, ptPt, ptBr, es419, zhHant, …)
// plus the full target-capable set the oneshot endpoint accepts.
//
// Keys are the uppercase forms callers pass; values are the lowercase
// BCP-47-ish forms oneshot expects ("de", "en-US", "zh-Hans", ...).
//
// EN and PT are intentionally absent as bare target codes — DeepL
// deprecated them in favour of EN-US/EN-GB and PT-BR/PT-PT. We accept
// EN/PT as a backward-compat convenience and resolve them to the
// regional default (en-US, pt-BR).
var targetLangMap = map[string]string{
	"AR": "ar", "BG": "bg", "CS": "cs", "DA": "da", "DE": "de", "DE-CH": "de-CH",
	"EL":    "el",
	"EN-GB": "en-GB", "EN-US": "en-US",
	"ES": "es", "ES-419": "es-419", "ET": "et", "FI": "fi", "FR": "fr", "FR-CA": "fr-CA",
	"HE": "he", "HU": "hu", "ID": "id", "IT": "it", "JA": "ja", "KO": "ko",
	"LT": "lt", "LV": "lv", "NB": "nb", "NL": "nl", "PL": "pl",
	"PT-BR": "pt-BR", "PT-PT": "pt-PT",
	"RO": "ro", "RU": "ru", "SK": "sk", "SL": "sl", "SV": "sv",
	"TR": "tr", "UK": "uk", "VI": "vi",
	"ZH": "zh-Hans", "ZH-HANS": "zh-Hans", "ZH-HANT": "zh-Hant",
	// Convenience aliases for legacy callers.
	"EN": "en-US",
	"PT": "pt-BR",
}

// sourceLangMap is what the API accepts as `source_lang`. It is a
// superset of targetLangMap: EN and PT are first-class source codes
// mapping to the generic "en"/"pt".
var sourceLangMap = func() map[string]string {
	m := make(map[string]string, len(targetLangMap)+2)
	for k, v := range targetLangMap {
		m[k] = v
	}
	m["EN"] = "en"
	m["PT"] = "pt"
	return m
}()

// resolveTargetLang validates and normalizes a user-supplied target
// language code. Returns "" and a non-nil error if the code is empty,
// "auto", or otherwise not in the supported set.
func resolveTargetLang(code string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("target_lang is required")
	}
	if strings.EqualFold(code, "auto") {
		return "", fmt.Errorf("target_lang cannot be \"auto\"; pick one of: %s", supportedTargetLangsList())
	}
	if v, ok := targetLangMap[strings.ToUpper(code)]; ok {
		return v, nil
	}
	return "", fmt.Errorf("unsupported target_lang %q; valid codes: %s", code, supportedTargetLangsList())
}

// resolveSourceLang validates and normalizes a user-supplied source
// language code. An empty string or "auto" is allowed and returns
// ("", nil) so the caller omits source_lang and lets the server
// autodetect.
func resolveSourceLang(code string) (string, error) {
	if code == "" || strings.EqualFold(code, "auto") {
		return "", nil
	}
	if v, ok := sourceLangMap[strings.ToUpper(code)]; ok {
		return v, nil
	}
	return "", fmt.Errorf("unsupported source_lang %q; valid codes: %s (or \"auto\")", code, supportedSourceLangsList())
}

// supportedTargetLangsList / supportedSourceLangsList return a sorted,
// comma-separated rendering of the supported codes for use in error
// messages. Cached at first call.
var (
	targetLangsListOnce sync.Once
	targetLangsList     string
	sourceLangsListOnce sync.Once
	sourceLangsList     string
)

func supportedTargetLangsList() string {
	targetLangsListOnce.Do(func() {
		targetLangsList = sortedKeys(targetLangMap)
	})
	return targetLangsList
}

func supportedSourceLangsList() string {
	sourceLangsListOnce.Do(func() {
		sourceLangsList = sortedKeys(sourceLangMap)
	})
	return sourceLangsList
}

func sortedKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func utf16CodeUnitCount(text string) int {
	count := 0
	for _, char := range text {
		count++
		if char > 0xffff {
			count++
		}
	}
	return count
}

func validateOneshotTextLength(text string, pro bool) error {
	if pro {
		if count := utf16CodeUnitCount(text); count > maxProTextLength {
			return fmt.Errorf(
				"text exceeds maximum length: %d UTF-16 code units (Pro oneshot limit is %d)",
				count,
				maxProTextLength,
			)
		}
		return nil
	}

	if count := utf8.RuneCountInString(text); count > maxFreeTextLength {
		return fmt.Errorf(
			"text exceeds maximum length: %d characters (anonymous oneshot limit is %d)",
			count,
			maxFreeTextLength,
		)
	}
	return nil
}

// appInformation is shared by the iOS and browser-extension oneshot bodies.
type appInformation struct {
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
	AppVersion string `json:"app_version"`
	AppBuild   string `json:"app_build"`
	InstanceID string `json:"instance_id"`
}

// oneshotRequest mirrors the body assembled by both interactive clients.
// Field order stays byte-stable because encoding/json honours struct order.
type oneshotRequest struct {
	Text           []string       `json:"text"`
	TargetLang     string         `json:"target_lang"`
	SourceLang     string         `json:"source_lang,omitempty"`
	UsageType      string         `json:"usage_type"`
	AppInformation appInformation `json:"app_information"`
}

func appInformationForProfile(profile ClientProfile) (appInformation, error) {
	switch profile {
	case ClientProfileIOS:
		return appInformation{
			OS:         "iOS",
			OSVersion:  iosOSVersion,
			AppVersion: iosAppVersion,
			AppBuild:   iosAppBuild,
			InstanceID: instanceID,
		}, nil
	case ClientProfileChrome:
		return appInformation{
			OS:         "brex_" + chromePlatform,
			OSVersion:  "brex_Chrome_" + chromeBrowserVersion,
			AppVersion: chromeExtensionVersion,
			AppBuild:   chromeAppBuild,
			InstanceID: instanceID,
		}, nil
	default:
		return appInformation{}, fmt.Errorf("unsupported DeepL client profile %q", profile)
	}
}

func newOneshotRequest(profile ClientProfile, text, targetLang, sourceLang string) (oneshotRequest, error) {
	appInfo, err := appInformationForProfile(profile)
	if err != nil {
		return oneshotRequest{}, err
	}
	return oneshotRequest{
		Text:           []string{text},
		TargetLang:     targetLang,
		SourceLang:     sourceLang,
		UsageType:      "translate",
		AppInformation: appInfo,
	}, nil
}

func oneshotClientCacheKey(profile ClientProfile, proxyURL string) string {
	return string(profile) + "\x00" + proxyURL
}

// getOneshotClient returns a process-wide cached client for the given
// proxy URL, creating it on first use. Sharing the client across
// requests keeps the TLS / HTTP/2 connection in the pool.
func getOneshotClient(profile ClientProfile, proxyURL string) (*req.Client, error) {
	key := oneshotClientCacheKey(profile, proxyURL)
	if c, ok := oneshotClients.Load(key); ok {
		return c.(*req.Client), nil
	}
	c, err := newOneshotClient(profile, proxyURL)
	if err != nil {
		return nil, err
	}
	if actual, loaded := oneshotClients.LoadOrStore(key, c); loaded {
		return actual.(*req.Client), nil
	}
	if profile == ClientProfileIOS {
		go warmCookies(c)
	}
	return c, nil
}

func newOneshotClient(profile ClientProfile, proxyURL string) (*req.Client, error) {
	var client *req.Client
	switch profile {
	case ClientProfileIOS:
		client = req.C().
			SetTLSFingerprintIOS().
			SetCookieJar(sharedCookieJar()).
			SetTimeout(oneshotTimeout).
			SetUserAgent(iosUserAgent()).
			SetCommonHeader("Accept-Encoding", "gzip, deflate, br").
			SetCommonHeader("Accept", "*/*").
			SetCommonHeader("Accept-Language", "en-US,en;q=0.9")
	case ClientProfileChrome:
		// ImpersonateChrome supplies Chrome-like HTTP/2 settings and header
		// ordering. Replace its navigation headers with the subset emitted by
		// a Manifest V3 service-worker JSON fetch, then move its ClientHello to
		// the newest Chrome profile available in the pinned uTLS version.
		client = req.C().ImpersonateChrome().SetTLSFingerprintChrome().SetCookieJar(nil)
		client.Headers = make(http.Header)
		client.SetTimeout(oneshotTimeout).
			SetUserAgent(chromeUserAgent()).
			SetCommonHeader("Accept-Encoding", "gzip, deflate, br").
			SetCommonHeader("Accept", "*/*").
			SetCommonHeader("Accept-Language", "en-US,en;q=0.9").
			SetCommonHeader("Sec-CH-UA", fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%s", "Google Chrome";v="%s"`, chromeBrowserMajor, chromeBrowserMajor)).
			SetCommonHeader("Sec-CH-UA-Mobile", "?0").
			SetCommonHeader("Sec-CH-UA-Platform", `"`+chromePlatform+`"`).
			SetCommonHeader("Origin", chromeExtensionOrigin).
			SetCommonHeader("Sec-Fetch-Site", "cross-site").
			SetCommonHeader("Sec-Fetch-Mode", "cors").
			SetCommonHeader("Sec-Fetch-Dest", "empty").
			SetCommonHeader("Priority", "u=1, i")
	default:
		return nil, fmt.Errorf("unsupported DeepL client profile %q", profile)
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		client.SetProxyURL(u.String())
	}
	return client, nil
}

// iosUserAgent is the URLSession product-style User-Agent the app's Ktor
// Darwin stack emits (CFBundleName/CFBundleShortVersionString + CFNetwork
// + Darwin). Do NOT invent alternate formats (e.g. embedding the bundle
// ID) — mismatched UA + iOS TLS fingerprint is a cheap ban signal.
func iosUserAgent() string {
	return fmt.Sprintf(
		"DeepL/%s CFNetwork/%s Darwin/%s",
		iosAppVersion, iosCFNetworkVersion, iosDarwinVersion,
	)
}

func chromeUserAgent() string {
	return fmt.Sprintf(
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		chromeBrowserVersion,
	)
}

const maxDiagnosticHeaderLength = 160

var diagnosticJSONFields = map[string]struct{}{
	"code":         {},
	"detail":       {},
	"error":        {},
	"errors":       {},
	"message":      {},
	"status":       {},
	"title":        {},
	"translations": {},
	"type":         {},
}

// boundedDiagnosticHeader keeps selected upstream metadata useful without
// allowing an unexpectedly large or multiline header to forge log entries.
func boundedDiagnosticHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxDiagnosticHeaderLength {
		value = value[:maxDiagnosticHeaderLength] + "..."
	}
	return value
}

// diagnosticResponseShape records only the presence of known JSON fields.
// Values and unknown field names are deliberately omitted because an upstream
// error response could reflect translated text, credentials, or other input.
func diagnosticResponseShape(raw []byte) (bool, string, int) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false, "", 0
	}

	fields := make([]string, 0, len(object))
	unknownFields := 0
	for field := range object {
		if _, ok := diagnosticJSONFields[field]; ok {
			fields = append(fields, field)
		} else {
			unknownFields++
		}
	}
	sort.Strings(fields)
	return true, strings.Join(fields, ","), unknownFields
}

func formatUpstreamDiagnostic(status int, profile ClientProfile, authenticated, viaProxy bool, proto string, headers http.Header, raw []byte) string {
	tier := "free"
	if authenticated {
		tier = "pro"
	}
	isJSON, jsonFields, unknownJSONFields := diagnosticResponseShape(raw)

	return fmt.Sprintf(
		"[DeepL upstream] status=%d profile=%s tier=%s via_proxy=%t proto=%q retry_after=%q request_id=%q trace_id=%q cf_ray=%q content_type=%q body_bytes=%d body_json=%t json_fields=%q unknown_json_fields=%d",
		status,
		profile,
		tier,
		viaProxy,
		boundedDiagnosticHeader(proto),
		boundedDiagnosticHeader(headers.Get("Retry-After")),
		boundedDiagnosticHeader(headers.Get("X-Request-ID")),
		boundedDiagnosticHeader(headers.Get("X-Trace-ID")),
		boundedDiagnosticHeader(headers.Get("CF-Ray")),
		boundedDiagnosticHeader(headers.Get("Content-Type")),
		len(raw),
		isJSON,
		jsonFields,
		unknownJSONFields,
	)
}

// callOneshot POSTs to the oneshot endpoint and returns the parsed JSON.
// For anonymous traffic bearerToken is empty and we send the literal
// header `Authorization: None` — matching ItaClient.LoginNone. Omitting
// that header puts the request on a different server-side auth branch.
func callOneshot(ctx context.Context, endpoint string, body []byte, bearerToken, proxyURL string, profile ClientProfile) (gjson.Result, int, error) {
	client, err := getOneshotClient(profile, proxyURL)
	if err != nil {
		return gjson.Result{}, 0, err
	}

	// LoginNone → literal "None"; LoginPro/Free → "Bearer <access_token>".
	authValue := "None"
	if bearerToken != "" {
		authValue = "Bearer " + bearerToken
	}

	request := client.R().
		SetContext(ctx).
		DisableAutoReadResponse().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", authValue)
	if profile == ClientProfileIOS {
		request.
			SetHeader("x-app-os-version", iosOSVersion).
			SetHeader("x-app-instance-id", instanceID).
			SetHeader("x-app-session-id", sessionID)
	}
	resp, err := request.
		SetBodyBytes(body). // Both clients send a fixed-length JSON body;
		// an io.Reader would force Transfer-Encoding: chunked.
		Post(endpoint)
	if err != nil {
		return gjson.Result{}, 0, err
	}
	defer resp.Body.Close()

	// Once we set Accept-Encoding ourselves, Go's HTTP stack stops
	// transparently decompressing, so handle gzip/deflate/br by hand.
	var reader io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return gjson.Result{}, resp.StatusCode, fmt.Errorf("gzip reader: %w", err)
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		fr := flate.NewReader(resp.Body)
		defer fr.Close()
		reader = fr
	case "br":
		reader = brotli.NewReader(resp.Body)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxOneshotResponseSize+1))
	if err != nil {
		return gjson.Result{}, resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}
	if len(raw) > maxOneshotResponseSize {
		return gjson.Result{}, resp.StatusCode, fmt.Errorf("upstream response exceeds %d bytes", maxOneshotResponseSize)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		log.Print(formatUpstreamDiagnostic(
			resp.StatusCode,
			profile,
			bearerToken != "",
			proxyURL != "",
			resp.Proto,
			resp.Header,
			raw,
		))
	}
	return gjson.ParseBytes(raw), resp.StatusCode, nil
}

// TranslateByDLX performs translation via the DeepL oneshot endpoint.
// Passing dlSession switches to the Pro endpoint; the value is sent
// verbatim as the Bearer token (i.e. it must be an OAuth access token,
// not the legacy dl_session cookie).
func TranslateByDLX(sourceLang, targetLang, text string, tagHandling string, proxyURL string, dlSession string) (DLXTranslationResult, error) {
	return TranslateByDLXContext(context.Background(), sourceLang, targetLang, text, tagHandling, proxyURL, dlSession)
}

// TranslateByDLXContext is TranslateByDLX with caller cancellation propagated
// to the upstream request. HTTP handlers should use this form so disconnected
// clients do not leave a DeepL request consuming resources until timeout.
func TranslateByDLXContext(ctx context.Context, sourceLang, targetLang, text string, tagHandling string, proxyURL string, dlSession string) (DLXTranslationResult, error) {
	return TranslateByDLXContextWithProfile(ctx, sourceLang, targetLang, text, tagHandling, proxyURL, dlSession, ClientProfileIOS)
}

// TranslateByDLXContextWithProfile performs oneshot translation with an
// explicitly selected interactive-client transport profile.
func TranslateByDLXContextWithProfile(ctx context.Context, sourceLang, targetLang, text string, tagHandling string, proxyURL string, dlSession string, profile ClientProfile) (DLXTranslationResult, error) {
	if text == "" {
		return DLXTranslationResult{
			Code:    http.StatusNotFound,
			Message: "No text to translate",
		}, nil
	}

	resolvedTarget, err := resolveTargetLang(targetLang)
	if err != nil {
		return DLXTranslationResult{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}, nil
	}
	resolvedSource, err := resolveSourceLang(sourceLang)
	if err != nil {
		return DLXTranslationResult{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}, nil
	}

	if err := validateOneshotTextLength(text, dlSession != ""); err != nil {
		return DLXTranslationResult{
			Code:    http.StatusRequestEntityTooLarge,
			Message: err.Error(),
		}, nil
	}

	// tagHandling is accepted by the public DLX API for compatibility
	// but oneshot does not expose html/xml tag handling the way the
	// official v2 API does — ignored upstream.
	_ = tagHandling

	reqStruct, err := newOneshotRequest(profile, text, resolvedTarget, resolvedSource)
	if err != nil {
		return DLXTranslationResult{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}, nil
	}
	bodyBytes, _ := json.Marshal(reqStruct)

	endpoint := oneshotFreeEndpoint
	if dlSession != "" {
		endpoint = oneshotProEndpoint
	}

	id := time.Now().UnixMilli()
	result, status, err := callOneshot(ctx, endpoint, bodyBytes, dlSession, proxyURL, profile)
	if err != nil {
		// Map upstream timeouts to 504 so callers can distinguish "DeepL
		// took too long" from other 503 failure modes (DNS, TLS, etc.).
		var ue *url.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ue) && ue.Timeout()) {
			return DLXTranslationResult{
				ID:      id,
				Code:    http.StatusGatewayTimeout,
				Message: fmt.Sprintf("upstream DeepL request timed out after %s", oneshotTimeout),
			}, nil
		}
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusServiceUnavailable,
			Message: err.Error(),
		}, nil
	}

	switch status {
	case http.StatusOK:
		// fall through to body parsing
	case http.StatusUnauthorized:
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusUnauthorized,
			Message: "DeepL Pro access token is invalid or expired",
		}, nil
	case http.StatusTooManyRequests:
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusTooManyRequests,
			Message: "too many requests, your IP has been blocked by DeepL temporarily, please don't request it frequently in a short time",
		}, nil
	case http.StatusRequestEntityTooLarge:
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusRequestEntityTooLarge,
			Message: "request exceeds the current DeepL oneshot payload limit",
		}, nil
	case http.StatusForbidden:
		// iOS surfaces this as OneShot: Forbidden / AuthenticationFailed /
		// OutdatedClient / UserBlocked depending on body; collapse to 403.
		msg := result.Get("title").String()
		if msg == "" {
			msg = result.Get("message").String()
		}
		if msg == "" {
			msg = "request forbidden by DeepL (auth failed, outdated client, or blocked)"
		}
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusForbidden,
			Message: msg,
		}, nil
	default:
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusServiceUnavailable,
			Message: fmt.Sprintf("request failed with status code: %d", status),
		}, nil
	}

	translations := result.Get("translations").Array()
	if len(translations) == 0 {
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusServiceUnavailable,
			Message: "Translation failed",
		}, nil
	}

	mainText := translations[0].Get("text").String()
	if mainText == "" {
		return DLXTranslationResult{
			ID:      id,
			Code:    http.StatusServiceUnavailable,
			Message: "Translation failed",
		}, nil
	}

	if detected := translations[0].Get("detected_source_language").String(); detected != "" {
		sourceLang = strings.ToUpper(detected)
	}

	return DLXTranslationResult{
		Code:         http.StatusOK,
		ID:           id,
		Data:         mainText,
		Alternatives: nil, // oneshot does not return alternatives
		SourceLang:   sourceLang,
		TargetLang:   targetLang,
		Method:       map[bool]string{true: "Pro", false: "Free"}[dlSession != ""],
	}, nil
}
