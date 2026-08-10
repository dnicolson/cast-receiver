package cast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeHTTPMediaURLAcceptsUnescapedIPv6Zone(t *testing.T) {
	source := "http://[fe80::1460:fbe4:2664:3ed1%en0]:8010/chromecast/686665053245/2104662727/stream"
	want := "http://[fe80::1460:fbe4:2664:3ed1%25en0]:8010/chromecast/686665053245/2104662727/stream"

	got := normalizeHTTPMediaURL(source)
	if got != want {
		t.Fatalf("normalizeHTTPMediaURL() = %q, want %q", got, want)
	}
	if _, err := url.Parse(got); err != nil {
		t.Fatalf("normalized URL should parse: %v", err)
	}
}

func TestNormalizeHTTPMediaURLLeavesEscapedIPv6Zone(t *testing.T) {
	source := "http://[fe80::1460:fbe4:2664:3ed1%25en0]:8010/stream"

	if got := normalizeHTTPMediaURL(source); got != source {
		t.Fatalf("normalizeHTTPMediaURL() = %q, want unchanged %q", got, source)
	}
}

func TestNormalizeHTTPMediaURLLeavesOtherURLs(t *testing.T) {
	tests := []string{
		"http://127.0.0.1:8010/stream",
		"http://[2001:db8::1]:8010/stream",
		"https://example.test/video%20name.mp4",
		"/tmp/video.mp4",
	}

	for _, source := range tests {
		t.Run(source, func(t *testing.T) {
			if got := normalizeHTTPMediaURL(source); got != source {
				t.Fatalf("normalizeHTTPMediaURL() = %q, want unchanged %q", got, source)
			}
		})
	}
}

func TestProxyMediaEmptySourceReturnsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	rr := httptest.NewRecorder()

	ProxyMedia(rr, req, "")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestProxyMediaRejectsNonGETOrHEAD(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/stream", nil)
			rr := httptest.NewRecorder()

			ProxyMedia(rr, req, "/does/not/matter")

			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestProxyMediaOptionsReturnsNoContentWithCORS(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/stream", nil)
	req.Header.Set("Origin", "http://example.com")
	rr := httptest.NewRecorder()

	ProxyMedia(rr, req, "/ignored-for-options")

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatal("expected Access-Control-Allow-Origin header to be set")
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("expected Access-Control-Allow-Methods header to be set")
	}
}

func TestProxyMediaDoesNotServeLocalPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(path, []byte("private data"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []string{
		path,
		"../../etc/passwd",
		"../secret.txt",
	}
	for _, source := range tests {
		t.Run(source, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/stream", nil)
			rr := httptest.NewRecorder()

			ProxyMedia(rr, req, source)

			if rr.Code != http.StatusBadGateway {
				t.Fatalf("status for %q = %d, want %d", source, rr.Code, http.StatusBadGateway)
			}
		})
	}
}

func TestProxyMediaProxiesRemoteURLWithCORS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := io.WriteString(w, "upstream-body"); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	req.Header.Set("Origin", "http://example-client")
	rr := httptest.NewRecorder()

	ProxyMedia(rr, req, u.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "upstream-body" {
		t.Fatalf("body = %q, want %q", rr.Body.String(), "upstream-body")
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatal("expected CORS headers on proxied response")
	}
}

func TestStreamHandlerProxiesRangeAndHead(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "video.mp4", time.Time{}, strings.NewReader("abcdef"))
	}))
	defer upstream.Close()
	receiver := NewReceiver(nil)
	receiver.Media.Media = &MediaInfo{ContentID: upstream.URL}

	for _, tc := range []struct {
		method, rangeHeader, body, length string
		status                            int
	}{
		{http.MethodGet, "bytes=2-4", "cde", "3", http.StatusPartialContent},
		{http.MethodHead, "", "", "6", http.StatusOK},
	} {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/stream", nil)
			req.Header.Set("Range", tc.rangeHeader)
			rr := httptest.NewRecorder()
			streamHandler(receiver)(rr, req)
			if rr.Code != tc.status || rr.Body.String() != tc.body {
				t.Fatalf("status/body = %d/%q, want %d/%q", rr.Code, rr.Body.String(), tc.status, tc.body)
			}
			if got := rr.Header().Get("Content-Length"); got != tc.length {
				t.Fatalf("Content-Length = %q, want %q", got, tc.length)
			}
			if tc.rangeHeader != "" && rr.Header().Get("Content-Range") != "bytes 2-4/6" {
				t.Fatalf("Content-Range = %q", rr.Header().Get("Content-Range"))
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Fatalf("CORS header = %q, want *", got)
			}
		})
	}
}
