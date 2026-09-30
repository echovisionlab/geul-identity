package mcpoauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthProxyDoesNotFollowUpstreamRedirects(t *testing.T) {
	var requests atomic.Int32
	upstream := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/followed" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.Header().Set("Location", "/followed")
		writer.WriteHeader(http.StatusFound)
	})
	handler := newTestHandler(t, upstream, http.NotFoundHandler(), rejectingHTTPClient())

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/followed" {
		t.Fatalf("facade response = %d Location=%q", response.Code, response.Header().Get("Location"))
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("authorization server requests = %d, want 1", got)
	}
}

func TestOAuthProxyFiltersRequestAndResponseHeaders(t *testing.T) {
	sourceRequest := make(http.Header)
	sourceRequest.Add("Accept", "application/json")
	sourceRequest.Add("User-Agent", "test-agent")
	sourceRequest.Add("Authorization", "Bearer allowed")
	sourceRequest.Add("Cookie", "session=allowed")
	sourceRequest.Add("X-Untrusted", "must-not-pass")
	targetRequest := make(http.Header)
	copyProxyRequestHeaders(
		targetRequest,
		sourceRequest,
		proxyAuthorizationHeader|proxyCookieHeader,
	)
	for name, want := range map[string]string{
		"Accept":        "application/json",
		"User-Agent":    "test-agent",
		"Authorization": "Bearer allowed",
		"Cookie":        "session=allowed",
	} {
		if got := targetRequest.Get(name); got != want {
			t.Errorf("forwarded %s = %q, want %q", name, got, want)
		}
	}
	if got := targetRequest.Get("X-Untrusted"); got != "" {
		t.Errorf("forwarded X-Untrusted = %q, want omitted", got)
	}
	withoutCredentials := make(http.Header)
	copyProxyRequestHeaders(withoutCredentials, sourceRequest, 0)
	if withoutCredentials.Get("Authorization") != "" || withoutCredentials.Get("Cookie") != "" {
		t.Fatalf("credentials passed without permission: %v", withoutCredentials)
	}

	sourceResponse := http.Header{
		"Content-Type":        {"application/json"},
		"Location":            {"https://issuer.example/login"},
		"Connection":          {"keep-alive"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authenticate":  {"Basic realm=\"internal\""},
		"Proxy-Authorization": {"Basic secret"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-Checksum"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"Content-Length":      {"32"},
		"Server":              {"internal"},
	}
	targetResponse := make(http.Header)
	copyProxyResponseHeaders(targetResponse, sourceResponse)
	if targetResponse.Get("Content-Type") != "application/json" ||
		targetResponse.Get("Location") != "https://issuer.example/login" {
		t.Fatalf("safe response headers missing: %v", targetResponse)
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Content-Length",
		"Server",
	} {
		if got := targetResponse.Get(name); got != "" {
			t.Errorf("forwarded blocked response header %s = %q", name, got)
		}
	}
}

func TestOAuthProxyPropagatesRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(cancelled)
	})
	handler := newTestHandler(t, upstream, http.NotFoundHandler(), rejectingHTTPClient())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(finished)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("authorization server request did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not reach authorization server")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("facade did not finish after request cancellation")
	}
	if response.Code != http.StatusBadGateway {
		t.Fatalf("cancelled facade status = %d, want %d", response.Code, http.StatusBadGateway)
	}
}
