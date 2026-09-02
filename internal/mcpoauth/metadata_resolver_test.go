package mcpoauth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type stubResolver struct {
	addresses []netip.Addr
	err       error
}

func (r stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, r.err
}

type stubDialer struct {
	mu        sync.Mutex
	addresses []string
	err       error
}

func (d *stubDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addresses = append(d.addresses, address)
	return nil, d.err
}

func (d *stubDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

func TestSafeDialRejectsPrivateAndMixedDNSWithoutConnecting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		addresses []netip.Addr
	}{
		{name: "loopback", addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "private", addresses: []netip.Addr{netip.MustParseAddr("10.0.0.8")}},
		{name: "link local", addresses: []netip.Addr{netip.MustParseAddr("169.254.169.254")}},
		{name: "cluster IPv6", addresses: []netip.Addr{netip.MustParseAddr("fd00::1")}},
		{name: "mixed public private", addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}},
		{name: "documentation", addresses: []netip.Addr{netip.MustParseAddr("203.0.113.8")}},
		{name: "NAT64", addresses: []netip.Addr{netip.MustParseAddr("64:ff9b::7f00:1")}},
		{name: "6to4", addresses: []netip.Addr{netip.MustParseAddr("2002:7f00:1::")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dialer := &stubDialer{err: errors.New("unexpected dial")}
			dial := safeDialContext(stubResolver{addresses: test.addresses}, dialer)
			if _, err := dial(context.Background(), "tcp", "client.example:443"); err == nil {
				t.Fatal("safe dial accepted a disallowed destination")
			}
			if calls := dialer.calls(); len(calls) != 0 {
				t.Fatalf("disallowed destination was dialed: %#v", calls)
			}
		})
	}
}

func TestSafeDialPinsValidatedPublicDNSResult(t *testing.T) {
	t.Parallel()
	dialer := &stubDialer{err: errors.New("dial stopped for test")}
	dial := safeDialContext(stubResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}, dialer)
	if _, err := dial(context.Background(), "tcp", "client.example:443"); err == nil {
		t.Fatal("expected stub dial failure")
	}
	if calls := dialer.calls(); len(calls) != 1 || calls[0] != "1.1.1.1:443" {
		t.Fatalf("dialed addresses = %#v", calls)
	}
}

func TestSafeMetadataClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var calls int
	client := &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://redirect.example/client.json"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
				Request:    request,
			}, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resolver, err := NewMetadataResolver(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "https://client.example/client.json"); err == nil {
		t.Fatal("redirecting metadata document was accepted")
	}
	if calls != 1 {
		t.Fatalf("metadata redirect made %d requests, want 1", calls)
	}
}

func TestMetadataResolverValidatesExactDocumentAndCachesWithinBound(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/client.json"
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":  []string{"application/json"},
				"Cache-Control": []string{"public, max-age=5"},
			},
			Body: io.NopCloser(strings.NewReader(`{
				"client_id":"https://client.example/client.json",
				"client_name":"Cached Client",
				"redirect_uris":["https://client.example/callback"],
				"token_endpoint_auth_method":"none"
			}`)),
			Request: request,
		}, nil
	})}
	resolver, err := NewMetadataResolver(client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 23, 0, 0, 0, 0, time.UTC)
	resolver.now = func() time.Time { return now }

	first, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || first.ClientName != "Cached Client" || second.ClientName != first.ClientName {
		t.Fatalf("metadata calls=%d first=%#v second=%#v", calls, first, second)
	}
	entry := resolver.cache[clientID]
	if got := entry.expiresAt.Sub(now); got != 5*time.Second {
		t.Fatalf("cache TTL = %s, want %s", got, 5*time.Second)
	}
}

func TestMetadataResolverRejectsInvalidResponseContracts(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/client.json"
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "wrong media type", contentType: "text/plain", body: `{}`},
		{name: "mismatched client id", contentType: "application/json", body: `{"client_id":"https://other.example/client.json","client_name":"Client","redirect_uris":["https://client.example/callback"]}`},
		{name: "duplicate field", contentType: "application/json", body: `{"client_id":"https://client.example/client.json","client_id":"https://client.example/client.json","client_name":"Client","redirect_uris":["https://client.example/callback"]}`},
		{name: "symmetric secret", contentType: "application/json", body: `{"client_id":"https://client.example/client.json","client_name":"Client","redirect_uris":["https://client.example/callback"],"client_secret":"forbidden"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{test.contentType}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
					Request:    request,
				}, nil
			})}
			resolver, err := NewMetadataResolver(client)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.Resolve(context.Background(), clientID); err == nil {
				t.Fatal("invalid metadata response was accepted")
			}
		})
	}
}

func TestMetadataResolverAcceptsJSONStructuredSuffixAndIgnoresExtensions(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/client.json"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/oauth-client-id-metadata+json; charset=utf-8"}},
			Body: io.NopCloser(strings.NewReader(`{
				"client_id":"https://client.example/client.json",
				"client_name":"Extended Client",
				"redirect_uris":["https://client.example/callback"],
				"token_endpoint_auth_method":"none",
				"example_extension":{"ignored":true}
			}`)),
			Request: request,
		}, nil
	})}
	resolver, err := NewMetadataResolver(client)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ClientID != clientID || metadata.ClientName != "Extended Client" ||
		len(metadata.RedirectURIs) != 1 || metadata.RedirectURIs[0] != "https://client.example/callback" {
		t.Fatalf("resolved metadata = %#v", metadata)
	}
}

func TestMetadataResolverEnforcesFiveKiBResponseLimitWithoutCachingFailure(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/client.json"
	valid := `{"client_id":"https://client.example/client.json","client_name":"Bounded Client","redirect_uris":["https://client.example/callback"]}`
	valid += strings.Repeat(" ", metadataResponseLimit-len(valid))
	oversized := valid + " "

	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body := oversized
		if calls > 1 {
			body = valid
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":  []string{"application/json"},
				"Cache-Control": []string{"public, max-age=60"},
			},
			Body:    io.NopCloser(strings.NewReader(body)),
			Request: request,
		}, nil
	})}
	resolver, err := NewMetadataResolver(client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 23, 0, 0, 0, 0, time.UTC)
	resolver.now = func() time.Time { return now }

	if _, err := resolver.Resolve(context.Background(), clientID); err == nil {
		t.Fatal("oversized metadata document was accepted")
	}
	if _, cached := resolver.cache[clientID]; cached {
		t.Fatal("oversized metadata document was cached")
	}

	now = now.Add(metadataHostRetryDelay)
	metadata, err := resolver.Resolve(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ClientID != clientID || metadata.ClientName != "Bounded Client" || calls != 2 {
		t.Fatalf("metadata=%#v calls=%d", metadata, calls)
	}
	if _, err := resolver.Resolve(context.Background(), clientID); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("valid metadata cache made %d fetches, want 2", calls)
	}
}

func TestMetadataCacheControlIsBounded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: metadataDefaultCacheTTL},
		{value: "max-age=1", want: time.Second},
		{value: "max-age=999999", want: metadataMaximumCacheTTL},
		{value: "no-store", want: 0},
		{value: "no-cache, max-age=300", want: 0},
		{value: "max-age=300, no-store", want: 0},
		{value: "max-age=300", want: 5 * time.Minute},
	}
	for _, test := range tests {
		if got := metadataCacheTTL(test.value); got != test.want {
			t.Errorf("metadataCacheTTL(%q) = %s, want %s", test.value, got, test.want)
		}
	}
}
