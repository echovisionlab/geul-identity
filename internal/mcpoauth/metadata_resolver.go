package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MCP 2025-11-25 pins CIMD draft-00's five-kilobyte recommendation.
	metadataResponseLimit    = 5 << 10
	metadataDefaultCacheTTL  = 15 * time.Minute
	metadataMaximumCacheTTL  = time.Hour
	metadataHostRetryDelay   = time.Second
	metadataCacheEntries     = 1024
	metadataFetchConcurrency = 8
)

type metadataCacheEntry struct {
	metadata  clientMetadata
	expiresAt time.Time
}

type metadataCall struct {
	done     chan struct{}
	metadata clientMetadata
	cacheTTL time.Duration
	err      error
}

// MetadataResolver fetches, validates, and bounds OAuth Client ID Metadata
// Documents. Its HTTP client must enforce the outbound network policy.
type MetadataResolver struct {
	client *http.Client
	now    func() time.Time

	mu            sync.Mutex
	cache         map[string]metadataCacheEntry
	inflight      map[string]*metadataCall
	hostLastFetch map[string]time.Time
	fetchSlots    chan struct{}
}

func NewMetadataResolver(client *http.Client) (*MetadataResolver, error) {
	if client == nil {
		return nil, errors.New("metadata HTTP client is required")
	}
	metadataClient := *client
	metadataClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &MetadataResolver{
		client:        &metadataClient,
		now:           time.Now,
		cache:         make(map[string]metadataCacheEntry),
		inflight:      make(map[string]*metadataCall),
		hostLastFetch: make(map[string]time.Time),
		fetchSlots:    make(chan struct{}, metadataFetchConcurrency),
	}, nil
}

func (r *MetadataResolver) Resolve(ctx context.Context, clientID string) (clientMetadata, error) {
	parsed, err := validateClientIDURL(clientID)
	if err != nil {
		return clientMetadata{}, err
	}
	now := r.now()
	host := strings.ToLower(parsed.Hostname())

	r.mu.Lock()
	if cached, ok := r.cache[clientID]; ok && now.Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.metadata, nil
	}
	if call, ok := r.inflight[clientID]; ok {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return clientMetadata{}, ctx.Err()
		case <-call.done:
			return call.metadata, call.err
		}
	}
	if lastFetch, ok := r.hostLastFetch[host]; ok && now.Sub(lastFetch) < metadataHostRetryDelay {
		r.mu.Unlock()
		return clientMetadata{}, errors.New("client metadata host fetch rate exceeded")
	}
	call := &metadataCall{done: make(chan struct{})}
	r.inflight[clientID] = call
	r.evictHostRateEntryLocked(now)
	r.hostLastFetch[host] = now
	r.mu.Unlock()

	select {
	case r.fetchSlots <- struct{}{}:
		call.metadata, call.cacheTTL, call.err = r.fetch(ctx, clientID)
		<-r.fetchSlots
	case <-ctx.Done():
		call.err = ctx.Err()
	}

	r.mu.Lock()
	delete(r.inflight, clientID)
	if call.err == nil {
		if ttl := call.cacheTTL; ttl > 0 {
			r.evictCacheEntryLocked()
			r.cache[clientID] = metadataCacheEntry{metadata: call.metadata, expiresAt: r.now().Add(ttl)}
		}
	}
	close(call.done)
	r.mu.Unlock()

	return call.metadata, call.err
}

func (r *MetadataResolver) evictHostRateEntryLocked(now time.Time) {
	if len(r.hostLastFetch) < metadataCacheEntries*2 {
		return
	}
	var oldestHost string
	var oldestFetch time.Time
	for host, fetchedAt := range r.hostLastFetch {
		if now.Sub(fetchedAt) >= metadataHostRetryDelay {
			delete(r.hostLastFetch, host)
			continue
		}
		if oldestHost == "" || fetchedAt.Before(oldestFetch) {
			oldestHost = host
			oldestFetch = fetchedAt
		}
	}
	if len(r.hostLastFetch) >= metadataCacheEntries*2 && oldestHost != "" {
		delete(r.hostLastFetch, oldestHost)
	}
}

func (r *MetadataResolver) fetch(ctx context.Context, clientID string) (clientMetadata, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return clientMetadata{}, 0, fmt.Errorf("create client metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return clientMetadata{}, 0, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return clientMetadata{}, 0, fmt.Errorf("client metadata returned HTTP %d", response.StatusCode)
	}
	if !isJSONMediaType(response.Header.Get("Content-Type")) {
		return clientMetadata{}, 0, errors.New("client metadata must use an application JSON media type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, metadataResponseLimit+1))
	if err != nil {
		return clientMetadata{}, 0, fmt.Errorf("read client metadata: %w", err)
	}
	if len(body) > metadataResponseLimit {
		return clientMetadata{}, 0, errors.New("client metadata exceeds the response size limit")
	}
	metadata, raw, err := decodeClientMetadata(body)
	if err != nil {
		return clientMetadata{}, 0, err
	}
	if err := rejectUnsafeRegistrationFields(raw, true); err != nil {
		return clientMetadata{}, 0, err
	}
	if metadata.ClientID != clientID {
		return clientMetadata{}, 0, errors.New("client metadata client_id does not exactly match its document URL")
	}
	metadata, err = normalizeClientMetadata(metadata, true)
	if err != nil {
		return clientMetadata{}, 0, err
	}
	return metadata, metadataCacheTTL(response.Header.Get("Cache-Control")), nil
}

func isJSONMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	if mediaType == "application/json" {
		return true
	}
	subtype, found := strings.CutPrefix(mediaType, "application/")
	return found && len(subtype) > len("+json") && strings.HasSuffix(subtype, "+json")
}

func (r *MetadataResolver) evictCacheEntryLocked() {
	if len(r.cache) < metadataCacheEntries {
		return
	}
	var oldestID string
	var oldestExpiry time.Time
	for clientID, entry := range r.cache {
		if oldestID == "" || entry.expiresAt.Before(oldestExpiry) {
			oldestID = clientID
			oldestExpiry = entry.expiresAt
		}
	}
	delete(r.cache, oldestID)
}

func metadataCacheTTL(cacheControl string) time.Duration {
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		name := strings.TrimSpace(strings.ToLower(strings.SplitN(directive, "=", 2)[0]))
		if name == "no-store" || name == "no-cache" {
			return 0
		}
	}
	for _, directive := range directives {
		parts := strings.SplitN(strings.TrimSpace(strings.ToLower(directive)), "=", 2)
		switch parts[0] {
		case "max-age":
			if len(parts) != 2 {
				continue
			}
			seconds, err := strconv.ParseInt(strings.Trim(parts[1], `"`), 10, 64)
			if err != nil || seconds <= 0 {
				return 0
			}
			ttl := time.Duration(seconds) * time.Second
			if ttl > metadataMaximumCacheTTL {
				return metadataMaximumCacheTTL
			}
			return ttl
		}
	}
	return metadataDefaultCacheTTL
}

type networkResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type networkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// NewSafeMetadataHTTPClient returns a direct, redirect-denying HTTP client.
// Every DNS result is checked before the connection is made, preventing proxy
// bypass and DNS rebinding into private or administrative networks.
func NewSafeMetadataHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDialContext(net.DefaultResolver, dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func safeDialContext(resolver networkResolver, dialer networkDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse metadata destination: %w", err)
		}
		if strings.Contains(host, "%") {
			return nil, errors.New("metadata destination cannot contain an IP zone")
		}

		var addresses []netip.Addr
		if literal, err := netip.ParseAddr(host); err == nil {
			addresses = []netip.Addr{literal.Unmap()}
		} else {
			addresses, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve metadata destination: %w", err)
			}
		}
		if len(addresses) == 0 {
			return nil, errors.New("metadata destination resolved to no addresses")
		}
		for _, address := range addresses {
			if !isPublicMetadataAddress(address.Unmap()) {
				return nil, fmt.Errorf("metadata destination resolved to disallowed address %s", address)
			}
		}

		var lastErr error
		for _, resolved := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("connect to metadata destination: %w", lastErr)
	}
}

var disallowedMetadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func isPublicMetadataAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range disallowedMetadataPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
