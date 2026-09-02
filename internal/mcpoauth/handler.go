package mcpoauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	protocolRequestLimit  = 64 << 10
	protocolResponseLimit = 2 << 20
	dynamicConcurrency    = 32
)

var (
	pkceChallengePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifierPattern    = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	dynamicClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,200}$`)
)

type proxyCredentialHeaders uint8

const (
	proxyAuthorizationHeader proxyCredentialHeaders = 1 << iota
	proxyCookieHeader
)

type HandlerConfig struct {
	Contract          Contract
	HydraPublicURL    string
	HydraPublicClient *http.Client
	MetadataResolver  *MetadataResolver
	HydraClients      *HydraClientManager
}

// Handler is the public MCP OAuth compatibility surface. Hydra remains the
// authorization server and owns login, consent, grants, access tokens, and
// revocation; this handler only validates and translates MCP protocol input.
type Handler struct {
	contract       Contract
	hydraPublicURL string
	issuerHost     string
	publicClient   *http.Client
	metadata       *MetadataResolver
	hydraClients   *HydraClientManager
	dynamicSlots   chan struct{}
	mux            *http.ServeMux
}

func NewHandler(config HandlerConfig) (*Handler, error) {
	if err := config.Contract.validate(); err != nil {
		return nil, fmt.Errorf("MCP OAuth contract: %w", err)
	}
	publicURL, err := validateUpstreamBaseURL(config.HydraPublicURL)
	if err != nil {
		return nil, fmt.Errorf("hydra public URL: %w", err)
	}
	if config.HydraPublicClient == nil {
		return nil, errors.New("hydra public HTTP client is required")
	}
	if config.MetadataResolver == nil {
		return nil, errors.New("client metadata resolver is required")
	}
	if config.HydraClients == nil {
		return nil, errors.New("hydra client manager is required")
	}
	issuerURL, err := url.Parse(config.Contract.IssuerURL)
	if err != nil || issuerURL.Host == "" {
		return nil, errors.New("MCP OAuth issuer origin is invalid")
	}
	publicClient := *config.HydraPublicClient
	publicClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	handler := &Handler{
		contract:       config.Contract,
		hydraPublicURL: publicURL,
		issuerHost:     issuerURL.Host,
		publicClient:   &publicClient,
		metadata:       config.MetadataResolver,
		hydraClients:   config.HydraClients,
		dynamicSlots:   make(chan struct{}, dynamicConcurrency),
		mux:            http.NewServeMux(),
	}
	handler.routes()
	return handler, nil
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /health/ready", h.handleReady)
	h.mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", h.handleProtectedResourceMetadata)
	h.mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleAuthorizationServerMetadata)
	h.mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	h.mux.HandleFunc("GET /oauth2/auth", h.handleAuthorize)
	h.mux.HandleFunc("GET /oauth2/fallbacks/error", h.handleAuthorizationError)
	h.mux.HandleFunc("POST /oauth2/token", h.handleToken)
	h.mux.HandleFunc("POST /oauth2/revoke", h.handleRevoke)
	h.mux.HandleFunc("POST /oauth2/register", h.handleRegister)
	h.mux.HandleFunc("GET /oauth2/register/{client_id}", h.handleRegistrationManagement)
	h.mux.HandleFunc("PUT /oauth2/register/{client_id}", h.handleRegistrationManagement)
	h.mux.HandleFunc("DELETE /oauth2/register/{client_id}", h.handleRegistrationManagement)
}

func (h *Handler) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	h.proxy(writer, request, http.MethodGet, "/.well-known/jwks.json", nil, nil, 0, false)
}

func (h *Handler) handleAuthorizationError(writer http.ResponseWriter, request *http.Request) {
	h.proxy(writer, request, http.MethodGet, "/oauth2/fallbacks/error", request.URL.Query(), nil, 0, false)
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.mux.ServeHTTP(writer, request)
}

func (h *Handler) handleReady(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"}, "no-store")
}

func (h *Handler) handleProtectedResourceMetadata(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"resource":                 h.contract.ResourceURL,
		"authorization_servers":    []string{h.contract.IssuerURL},
		"scopes_supported":         []string{Scope},
		"bearer_methods_supported": []string{"header"},
	}, "public, max-age=300")
}

func (h *Handler) handleAuthorizationServerMetadata(writer http.ResponseWriter, request *http.Request) {
	metadata := map[string]any{
		"issuer":                                h.contract.IssuerURL,
		"authorization_endpoint":                h.contract.IssuerURL + "/oauth2/auth",
		"token_endpoint":                        h.contract.IssuerURL + "/oauth2/token",
		"revocation_endpoint":                   h.contract.IssuerURL + "/oauth2/revoke",
		"jwks_uri":                              h.contract.IssuerURL + "/.well-known/jwks.json",
		"scopes_supported":                      []string{Scope, OfflineAccessScope},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		"revocation_endpoint_auth_methods_supported":       []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
	}
	metadata["registration_endpoint"] = h.contract.IssuerURL + "/oauth2/register"
	metadata["client_id_metadata_document_supported"] = true
	writeJSON(writer, http.StatusOK, metadata, "no-store")
}

func (h *Handler) handleAuthorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	continuation, err := hydraAuthorizationContinuation(query)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientID, err := singleRequired(query, "client_id")
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	redirectURI, err := singleRequired(query, "redirect_uri")
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateRedirectURI(redirectURI); err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "redirect_uri is invalid")
		return
	}
	if !singleEquals(query, "response_type", "code") {
		writeProtocolError(writer, http.StatusBadRequest, "unsupported_response_type", "response_type must be code")
		return
	}
	if !hasMCPAuthorizationScopes(query["scope"]) {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_scope", "scope must be mcp with optional offline_access")
		return
	}
	if err := requireExactResource(query, h.contract.ResourceURL); err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	if len(query["request"]) != 0 || len(query["request_uri"]) != 0 {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "audience and request object parameters are not accepted on the MCP facade")
		return
	}
	if continuation {
		if !singleEquals(query, "audience", h.contract.ResourceURL) {
			writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "authorization continuation audience is invalid")
			return
		}
	} else if len(query["audience"]) != 0 {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "audience and request object parameters are not accepted on the MCP facade")
		return
	}
	challenge, err := singleRequired(query, "code_challenge")
	if err != nil || !pkceChallengePattern.MatchString(challenge) || !singleEquals(query, "code_challenge_method", "S256") {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "PKCE S256 is required")
		return
	}

	if looksLikeURLClientID(clientID) && !continuation {
		if _, err := validateClientIDURL(clientID); err != nil {
			writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "URL-form client_id is invalid")
			return
		}
		if !h.beginDynamic(writer) {
			return
		}
		defer h.endDynamic()
		metadata, err := h.metadata.Resolve(request.Context(), clientID)
		if err != nil {
			writeProtocolError(writer, http.StatusBadRequest, "invalid_client", "client metadata document is unavailable or invalid")
			return
		}
		if !slices.Contains(metadata.RedirectURIs, redirectURI) {
			writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "redirect_uri does not exactly match client metadata")
			return
		}
		if err := h.hydraClients.EnsureCIMDClient(request.Context(), metadata); err != nil {
			writeProtocolError(writer, http.StatusBadGateway, "temporarily_unavailable", "client registration could not be synchronized")
			return
		}
	}

	if !continuation {
		query.Set("audience", h.contract.ResourceURL)
	}
	h.proxy(writer, request, http.MethodGet, "/oauth2/auth", query, nil, proxyCookieHeader, false)
}

func hydraAuthorizationContinuation(query url.Values) (bool, error) {
	verifierName := ""
	for _, name := range []string{"login_verifier", "consent_verifier"} {
		if _, present := query[name]; present {
			if verifierName != "" {
				return false, errors.New("authorization continuation must contain exactly one verifier")
			}
			verifierName = name
		}
	}
	if verifierName == "" {
		return false, nil
	}
	values := query[verifierName]
	if len(values) != 1 || values[0] == "" || len(values[0]) > 2048 {
		return false, errors.New("authorization continuation must contain exactly one valid verifier")
	}
	return true, nil
}

func (h *Handler) handleToken(writer http.ResponseWriter, request *http.Request) {
	form, err := readForm(request)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := requireExactResource(form, h.contract.ResourceURL); err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	if len(form["audience"]) != 0 {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "audience is not accepted on the MCP facade")
		return
	}
	grantType, err := singleRequired(form, "grant_type")
	if err != nil || (grantType != "authorization_code" && grantType != "refresh_token") {
		writeProtocolError(writer, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		return
	}
	if grantType == "authorization_code" {
		verifier, verifierErr := singleRequired(form, "code_verifier")
		if verifierErr != nil || !pkceVerifierPattern.MatchString(verifier) {
			writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "a valid PKCE code_verifier is required")
			return
		}
	} else if _, refreshErr := singleRequired(form, "refresh_token"); refreshErr != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if scopes := form["scope"]; len(scopes) != 0 && !hasMCPAuthorizationScopes(scopes) {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_scope", "scope must be mcp with optional offline_access when supplied")
		return
	}
	form.Set("audience", h.contract.ResourceURL)
	h.proxy(writer, request, http.MethodPost, "/oauth2/token", nil, []byte(form.Encode()), proxyAuthorizationHeader, false)
}

func (h *Handler) handleRevoke(writer http.ResponseWriter, request *http.Request) {
	form, err := readForm(request)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, err := singleRequired(form, "token"); err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	h.proxy(writer, request, http.MethodPost, "/oauth2/revoke", nil, []byte(form.Encode()), proxyAuthorizationHeader, false)
}

func (h *Handler) handleRegister(writer http.ResponseWriter, request *http.Request) {
	if !h.beginDynamic(writer) {
		return
	}
	defer h.endDynamic()
	body, err := readJSONBody(request)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	metadata, raw, err := decodeClientMetadata(body)
	if err != nil || rejectUnsafeRegistrationFields(raw, false) != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client_metadata", "dynamic client metadata is invalid")
		return
	}
	metadata, err = normalizeClientMetadata(metadata, false)
	if err != nil {
		code := "invalid_client_metadata"
		if strings.Contains(err.Error(), "redirect_uri") {
			code = "invalid_redirect_uri"
		}
		writeProtocolError(writer, http.StatusBadRequest, code, err.Error())
		return
	}
	normalized, err := json.Marshal(h.hydraDynamicRegistration(metadata))
	if err != nil {
		writeProtocolError(writer, http.StatusInternalServerError, "server_error", "registration metadata could not be encoded")
		return
	}
	h.proxy(writer, request, http.MethodPost, "/oauth2/register", nil, normalized, 0, true)
}

func (h *Handler) handleRegistrationManagement(writer http.ResponseWriter, request *http.Request) {
	if !h.beginDynamic(writer) {
		return
	}
	defer h.endDynamic()
	clientID := request.PathValue("client_id")
	if !dynamicClientIDPattern.MatchString(clientID) {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client", "registration client_id is invalid")
		return
	}
	path := "/oauth2/register/" + url.PathEscape(clientID)
	if request.Method != http.MethodPut {
		h.proxy(writer, request, request.Method, path, nil, nil, proxyAuthorizationHeader, true)
		return
	}
	body, err := readJSONBody(request)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	metadata, raw, err := decodeClientMetadata(body)
	if err != nil || rejectUnsafeRegistrationFields(raw, true) != nil || (metadata.ClientID != "" && metadata.ClientID != clientID) {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client_metadata", "dynamic client metadata is invalid")
		return
	}
	metadata.ClientID = ""
	metadata, err = normalizeClientMetadata(metadata, false)
	if err != nil {
		writeProtocolError(writer, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	normalized, err := json.Marshal(h.hydraDynamicRegistration(metadata))
	if err != nil {
		writeProtocolError(writer, http.StatusInternalServerError, "server_error", "registration metadata could not be encoded")
		return
	}
	h.proxy(writer, request, http.MethodPut, path, nil, normalized, proxyAuthorizationHeader, true)
}

func (h *Handler) hydraDynamicRegistration(metadata clientMetadata) map[string]any {
	return map[string]any{
		"client_name":                metadata.ClientName,
		"redirect_uris":              metadata.RedirectURIs,
		"grant_types":                metadata.GrantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      hydraClientScope,
		"audience":                   []string{h.contract.ResourceURL},
		"skip_consent":               false,
	}
}

func (h *Handler) beginDynamic(writer http.ResponseWriter) bool {
	select {
	case h.dynamicSlots <- struct{}{}:
		return true
	default:
		writer.Header().Set("Retry-After", "1")
		writeProtocolError(writer, http.StatusTooManyRequests, "temporarily_unavailable", "dynamic client request concurrency exceeded")
		return false
	}
}

func (h *Handler) endDynamic() {
	<-h.dynamicSlots
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

func (h *Handler) rewriteRegistrationResponse(body []byte, headers http.Header) ([]byte, error) {
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	clientID, ok := response["client_id"].(string)
	if !ok || !dynamicClientIDPattern.MatchString(clientID) {
		return nil, errors.New("registration response client_id is invalid")
	}
	registrationURI := h.contract.IssuerURL + "/oauth2/register/" + url.PathEscape(clientID)
	response["registration_client_uri"] = registrationURI
	headers.Set("Location", registrationURI)
	return json.Marshal(response)
}

func readJSONBody(request *http.Request) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("content type must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, protocolRequestLimit+1))
	if err != nil {
		return nil, errors.New("request body could not be read")
	}
	if len(body) > protocolRequestLimit {
		return nil, errors.New("request body exceeds the size limit")
	}
	return body, nil
}

func readForm(request *http.Request) (url.Values, error) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, errors.New("content type must be application/x-www-form-urlencoded")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, protocolRequestLimit+1))
	if err != nil {
		return nil, errors.New("request body could not be read")
	}
	if len(body) > protocolRequestLimit {
		return nil, errors.New("request body exceeds the size limit")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, errors.New("request form is invalid")
	}
	return form, nil
}

func singleRequired(values url.Values, name string) (string, error) {
	items := values[name]
	if len(items) != 1 || items[0] == "" {
		return "", fmt.Errorf("%s must be supplied exactly once", name)
	}
	return items[0], nil
}

func singleEquals(values url.Values, name, expected string) bool {
	items := values[name]
	return len(items) == 1 && items[0] == expected
}

func hasMCPAuthorizationScopes(values []string) bool {
	if len(values) != 1 {
		return false
	}
	scopes := strings.Fields(values[0])
	return sameStringSet(scopes, []string{Scope}) ||
		sameStringSet(scopes, []string{Scope, OfflineAccessScope})
}

func requireExactResource(values url.Values, expected string) error {
	resource := values["resource"]
	if len(resource) != 1 || resource[0] != expected {
		return fmt.Errorf("resource must be exactly %s", expected)
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any, cacheControl string) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", cacheControl)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func writeProtocolError(writer http.ResponseWriter, status int, code, description string) {
	writeJSON(writer, status, map[string]string{
		"error":             code,
		"error_description": description,
	}, "no-store")
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
