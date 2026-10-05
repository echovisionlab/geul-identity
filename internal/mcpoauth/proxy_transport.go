package mcpoauth

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	protocolRequestLimit  = 64 << 10
	protocolResponseLimit = 2 << 20
)

type proxyCredentialHeaders uint8

const (
	proxyAuthorizationHeader proxyCredentialHeaders = 1 << iota
	proxyCookieHeader
)

func newOAuthProxyClient(client *http.Client) *http.Client {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copy
}

func (h *Handler) proxy(
	writer http.ResponseWriter,
	original *http.Request,
	method string,
	path string,
	query url.Values,
	body []byte,
	credentialHeaders proxyCredentialHeaders,
	rewriteRegistration bool,
) {
	target := h.hydraPublicURL + path
	if len(query) != 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(original.Context(), method, target, bytes.NewReader(body))
	if err != nil {
		writeProtocolError(writer, http.StatusBadGateway, "temporarily_unavailable", "authorization server request could not be created")
		return
	}
	copyProxyRequestHeaders(req.Header, original.Header, credentialHeaders)
	req.Host = h.issuerHost
	req.Header.Set("X-Forwarded-Host", h.issuerHost)
	req.Header.Set("X-Forwarded-Proto", "https")
	if body != nil {
		if path == "/oauth2/register" || strings.HasPrefix(path, "/oauth2/register/") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	response, err := h.publicClient.Do(req)
	if err != nil {
		writeProtocolError(writer, http.StatusBadGateway, "temporarily_unavailable", "authorization server is unavailable")
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, protocolResponseLimit+1))
	if err != nil || len(responseBody) > protocolResponseLimit {
		writeProtocolError(writer, http.StatusBadGateway, "temporarily_unavailable", "authorization server response is invalid")
		return
	}
	copyProxyResponseHeaders(writer.Header(), response.Header)
	if rewriteRegistration && len(responseBody) != 0 && response.StatusCode >= 200 && response.StatusCode < 300 {
		responseBody, err = h.rewriteRegistrationResponse(responseBody, writer.Header())
		if err != nil {
			clearHeaders(writer.Header())
			writeProtocolError(writer, http.StatusBadGateway, "temporarily_unavailable", "registration server response is invalid")
			return
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(responseBody)
}

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func copyProxyRequestHeaders(target, source http.Header, credentialHeaders proxyCredentialHeaders) {
	names := []string{"Accept", "User-Agent"}
	if credentialHeaders&proxyAuthorizationHeader != 0 {
		names = append(names, "Authorization")
	}
	if credentialHeaders&proxyCookieHeader != 0 {
		names = append(names, "Cookie")
	}
	for _, name := range names {
		for _, value := range source.Values(name) {
			target.Add(name, value)
		}
	}
}

func clearHeaders(headers http.Header) {
	for name := range headers {
		headers.Del(name)
	}
}

func copyProxyResponseHeaders(target, source http.Header) {
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if _, excluded := hopByHopHeaders[canonical]; excluded || canonical == "Content-Length" || canonical == "Server" {
			continue
		}
		for _, value := range values {
			target.Add(canonical, value)
		}
	}
}
