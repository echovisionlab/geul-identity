package mcpoauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const testPKCEVerifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

var testPKCEChallenge = func() string {
	digest := sha256.Sum256([]byte(testPKCEVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}()

func TestDiscoveryAdvertisesValidatedDynamicCapabilities(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, http.NotFoundHandler(), http.NotFoundHandler(), rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	protected := getJSON(t, server.URL+"/.well-known/oauth-protected-resource/mcp")
	if protected["resource"] != testContract.ResourceURL {
		t.Fatalf("protected resource = %#v", protected["resource"])
	}
	authorizationServers := stringSlice(t, protected["authorization_servers"])
	if len(authorizationServers) != 1 || authorizationServers[0] != testContract.IssuerURL {
		t.Fatalf("authorization_servers = %#v", authorizationServers)
	}

	metadata := getJSON(t, server.URL+"/.well-known/oauth-authorization-server")
	if metadata["issuer"] != testContract.IssuerURL || metadata["authorization_endpoint"] != testContract.IssuerURL+"/oauth2/auth" ||
		metadata["token_endpoint"] != testContract.IssuerURL+"/oauth2/token" {
		t.Fatalf("authorization server metadata = %#v", metadata)
	}
	if metadata["registration_endpoint"] != testContract.IssuerURL+"/oauth2/register" {
		t.Fatalf("registration endpoint = %#v", metadata["registration_endpoint"])
	}
	if metadata["client_id_metadata_document_supported"] != true {
		t.Fatalf("CIMD support = %#v", metadata["client_id_metadata_document_supported"])
	}
	methods := stringSlice(t, metadata["code_challenge_methods_supported"])
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("PKCE methods = %#v", methods)
	}
	grantTypes := stringSlice(t, metadata["grant_types_supported"])
	if !sameStringSet(grantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("grant types = %#v", grantTypes)
	}
	scopes := stringSlice(t, metadata["scopes_supported"])
	if !sameStringSet(scopes, []string{Scope, OfflineAccessScope}) {
		t.Fatalf("authorization server scopes = %#v", scopes)
	}
	signingAlgorithms := stringSlice(t, metadata["token_endpoint_auth_signing_alg_values_supported"])
	if len(signingAlgorithms) != 1 || signingAlgorithms[0] != "RS256" {
		t.Fatalf("token endpoint signing algorithms = %#v", signingAlgorithms)
	}
}

func TestIssuerPublicReadSurfacesStayBehindFacade(t *testing.T) {
	t.Parallel()
	var paths []string
	public := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.RequestURI())
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatalf("public read forwarded caller credentials")
		}
		switch request.URL.Path {
		case "/.well-known/jwks.json":
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "public, max-age=300")
			_, _ = io.WriteString(writer, `{"keys":[]}`)
		case "/oauth2/fallbacks/error":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, "authorization failed")
		default:
			t.Fatalf("unexpected Hydra public path %s", request.URL.Path)
		}
	})
	handler := newTestHandler(t, public, http.NotFoundHandler(), rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/.well-known/jwks.json", nil)
	request.Header.Set("Authorization", "Bearer must-not-reach-hydra")
	request.Header.Set("Cookie", "hydra_login=must-not-reach-hydra")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "public, max-age=300" {
		response.Body.Close()
		t.Fatalf("JWKS response status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	response.Body.Close()

	response, err = http.Get(server.URL + "/oauth2/fallbacks/error?error=access_denied&state=opaque")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		response.Body.Close()
		t.Fatalf("fallback response status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	response.Body.Close()

	if strings.Join(paths, ",") != "/.well-known/jwks.json,/oauth2/fallbacks/error?error=access_denied&state=opaque" {
		t.Fatalf("Hydra public read paths = %#v", paths)
	}
}

func TestDCRMediationNormalizesHydraRegistration(t *testing.T) {
	t.Parallel()
	var received map[string]any
	public := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/oauth2/register" {
			t.Fatalf("Hydra public request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatalf("DCR registration forwarded caller credentials")
		}
		decodeJSONBody(t, request.Body, &received)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Location", "http://hydra.internal/admin/clients/dynamic-1")
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, `{"client_id":"dynamic-1","registration_access_token":"registration-token","registration_client_uri":"http://hydra.internal/oauth2/register/dynamic-1"}`)
	})
	handler := newTestHandler(t, public, http.NotFoundHandler(), rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	requestBody, err := json.Marshal(map[string]any{
		"client_name":                "Example MCP",
		"redirect_uris":              []string{"http://127.0.0.1:49152/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      hydraClientScope,
		"logo_uri":                   "https://client.example/logo.png",
		"software_id":                "example-software",
		"example_extension":          map[string]any{"ignored": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/register", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer must-not-reach-hydra")
	request.Header.Set("Cookie", "hydra_login=must-not-reach-hydra")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("DCR status = %d body=%s", response.StatusCode, body)
	}
	if response.Header.Get("Location") != testContract.IssuerURL+"/oauth2/register/dynamic-1" {
		t.Fatalf("DCR Location = %q", response.Header.Get("Location"))
	}
	var registration map[string]any
	decodeJSONBody(t, response.Body, &registration)
	if registration["registration_client_uri"] != testContract.IssuerURL+"/oauth2/register/dynamic-1" ||
		registration["registration_access_token"] != "registration-token" {
		t.Fatalf("DCR response = %#v", registration)
	}
	if received["client_name"] != "Example MCP" || received["scope"] != hydraClientScope || received["token_endpoint_auth_method"] != "none" {
		t.Fatalf("normalized DCR body = %#v", received)
	}
	grantTypes := stringSlice(t, received["grant_types"])
	if !sameStringSet(grantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("DCR grant types = %#v", grantTypes)
	}
	if received["scope"] != hydraClientScope {
		t.Fatalf("DCR Hydra scope = %#v", received["scope"])
	}
	if _, present := received["logo_uri"]; present {
		t.Fatalf("remote logo propagated to Hydra: %#v", received)
	}
	if _, present := received["software_id"]; present {
		t.Fatalf("untrusted software metadata propagated to Hydra: %#v", received)
	}
	if _, present := received["example_extension"]; present {
		t.Fatalf("unrecognized client metadata extension propagated to Hydra: %#v", received)
	}
	if received["skip_consent"] != false {
		t.Fatalf("skip_consent = %#v", received["skip_consent"])
	}
	audiences := stringSlice(t, received["audience"])
	if len(audiences) != 1 || audiences[0] != testContract.ResourceURL {
		t.Fatalf("DCR audience = %#v", audiences)
	}
}

func TestDCRManagementStaysOnFacadeAndHydraOwnsRegistrationCredential(t *testing.T) {
	t.Parallel()
	var methods []string
	var updated map[string]any
	public := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		if request.URL.Path != "/oauth2/register/dynamic-1" || request.Header.Get("Authorization") != "Bearer registration-token" ||
			request.Header.Get("Cookie") != "" {
			t.Fatalf("Hydra management request = %s %s Authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		switch request.Method {
		case http.MethodGet:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"client_id":"dynamic-1","client_name":"Existing","redirect_uris":["https://client.example/callback"],"registration_client_uri":"http://hydra.internal/oauth2/register/dynamic-1"}`)
		case http.MethodPut:
			decodeJSONBody(t, request.Body, &updated)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"client_id":"dynamic-1","client_name":"Updated","redirect_uris":["https://client.example/callback"]}`)
		case http.MethodDelete:
			writer.WriteHeader(http.StatusNoContent)
		}
	})
	handler := newTestHandler(t, public, http.NotFoundHandler(), rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		var body io.Reader
		if method == http.MethodPut {
			encoded, _ := json.Marshal(map[string]any{
				"client_id":                  "dynamic-1",
				"client_name":                "Updated",
				"redirect_uris":              []string{"https://client.example/callback"},
				"token_endpoint_auth_method": "none",
			})
			body = bytes.NewReader(encoded)
		}
		request, _ := http.NewRequest(method, server.URL+"/oauth2/register/dynamic-1", body)
		request.Header.Set("Authorization", "Bearer registration-token")
		request.Header.Set("Cookie", "hydra_login=must-not-reach-hydra")
		if method == http.MethodPut {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s status=%d body=%s", method, response.StatusCode, responseBody)
		}
		if method != http.MethodDelete {
			var result map[string]any
			if err := json.Unmarshal(responseBody, &result); err != nil {
				t.Fatal(err)
			}
			if result["registration_client_uri"] != testContract.IssuerURL+"/oauth2/register/dynamic-1" {
				t.Fatalf("%s registration_client_uri = %#v", method, result["registration_client_uri"])
			}
		}
	}
	if strings.Join(methods, ",") != "GET,PUT,DELETE" {
		t.Fatalf("Hydra management methods = %#v", methods)
	}
	if updated["scope"] != hydraClientScope || updated["skip_consent"] != false {
		t.Fatalf("normalized management update = %#v", updated)
	}
}

func TestStaticAuthorizationAndTokenPreserveHydraAuthority(t *testing.T) {
	t.Parallel()
	var adminCalls atomic.Int32
	var tokenCalls atomic.Int32
	var authQuery url.Values
	var authCookie string
	var authAuthorization string
	var authForwardedHost string
	var authForwardedProto string
	var authHost string
	var tokenForm url.Values
	var tokenAuthorization string
	var tokenCookie string
	public := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth2/auth":
			authQuery = request.URL.Query()
			authCookie = request.Header.Get("Cookie")
			authAuthorization = request.Header.Get("Authorization")
			authForwardedHost = request.Header.Get("X-Forwarded-Host")
			authForwardedProto = request.Header.Get("X-Forwarded-Proto")
			authHost = request.Host
			writer.Header().Set("Location", testContract.SiteOrigin+"/login")
			writer.WriteHeader(http.StatusFound)
		case "/oauth2/token":
			tokenCalls.Add(1)
			body, _ := io.ReadAll(request.Body)
			tokenForm, _ = url.ParseQuery(string(body))
			tokenAuthorization = request.Header.Get("Authorization")
			tokenCookie = request.Header.Get("Cookie")
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"hydra-token","token_type":"bearer"}`)
		default:
			t.Fatalf("unexpected Hydra public path %s", request.URL.Path)
		}
	})
	handler := newTestHandler(t, public, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		adminCalls.Add(1)
	}), rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	authorizeURL := authorizationURL(server.URL, "static-client", "https://client.example/callback")
	authorizeRequest, _ := http.NewRequest(http.MethodGet, authorizeURL, nil)
	authorizeRequest.Header.Set("Cookie", "hydra_login=remembered")
	authorizeRequest.Header.Set("Authorization", "Basic must-not-reach-hydra")
	authorizeRequest.Header.Set("X-Forwarded-Host", "attacker.example")
	authorizeRequest.Header.Set("X-Forwarded-Proto", "http")
	authorizeClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := authorizeClient.Do(authorizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != testContract.SiteOrigin+"/login" {
		t.Fatalf("authorization response = %d Location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	if authQuery.Get("resource") != testContract.ResourceURL || authQuery.Get("audience") != testContract.ResourceURL {
		t.Fatalf("Hydra authorization query = %#v", authQuery)
	}
	if authCookie != "hydra_login=remembered" || authAuthorization != "" {
		t.Fatalf("Hydra authorization Cookie=%q Authorization=%q", authCookie, authAuthorization)
	}
	if authForwardedHost != "sso.example" || authForwardedProto != "https" || authHost != "sso.example" {
		t.Fatalf("Hydra trusted proxy boundary Host=%q forwarded-host=%q forwarded-proto=%q", authHost, authForwardedHost, authForwardedProto)
	}
	if adminCalls.Load() != 0 {
		t.Fatalf("opaque static client touched Hydra Admin %d times", adminCalls.Load())
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"static-client"},
		"code":          {"authorization-code"},
		"code_verifier": {testPKCEVerifier},
		"redirect_uri":  {"https://client.example/callback"},
		"resource":      {testContract.ResourceURL},
	}
	tokenRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set("Authorization", "Basic client-auth")
	tokenRequest.Header.Set("Cookie", "hydra_login=must-not-reach-hydra")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", tokenResponse.StatusCode)
	}
	if tokenForm.Get("resource") != testContract.ResourceURL || tokenForm.Get("audience") != testContract.ResourceURL ||
		tokenAuthorization != "Basic client-auth" || tokenCookie != "" {
		t.Fatalf("Hydra token form=%#v Authorization=%q Cookie=%q", tokenForm, tokenAuthorization, tokenCookie)
	}

	signedResponse := postForm(t, server.URL+"/oauth2/token", url.Values{
		"grant_type":            {"authorization_code"},
		"client_id":             {"https://client.example/client.json"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {"signed-client-assertion"},
		"code":                  {"signed-authorization-code"},
		"code_verifier":         {testPKCEVerifier},
		"redirect_uri":          {"https://client.example/callback"},
		"resource":              {testContract.ResourceURL},
	})
	signedResponse.Body.Close()
	if signedResponse.StatusCode != http.StatusOK ||
		tokenForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
		tokenForm.Get("client_assertion") != "signed-client-assertion" || tokenAuthorization != "" || tokenCookie != "" {
		t.Fatalf("Hydra signed token form=%#v Authorization=%q Cookie=%q", tokenForm, tokenAuthorization, tokenCookie)
	}

	refreshResponse := postForm(t, server.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"static-client"},
		"refresh_token": {"refresh-token"},
		"resource":      {testContract.ResourceURL},
	})
	refreshResponse.Body.Close()
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d", refreshResponse.StatusCode, http.StatusOK)
	}
	if tokenCalls.Load() != 3 || tokenForm.Get("grant_type") != "refresh_token" ||
		tokenForm.Get("refresh_token") != "refresh-token" || tokenForm.Get("audience") != testContract.ResourceURL {
		t.Fatalf("refresh grant was not preserved for Hydra: calls=%d form=%#v", tokenCalls.Load(), tokenForm)
	}

	badURL := authorizationURL(server.URL, "static-client", "https://client.example/callback")
	parsed, _ := url.Parse(badURL)
	query := parsed.Query()
	query.Set("resource", testContract.SiteOrigin+"/other")
	parsed.RawQuery = query.Encode()
	badResponse := getWithoutRedirect(t, parsed.String())
	defer badResponse.Body.Close()
	if badResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong resource status = %d", badResponse.StatusCode)
	}
}

func TestCIMDAuthorizationFetchesAndRegistersOnlyValidatedClient(t *testing.T) {
	t.Parallel()
	redirectURI := "https://client.example/callback"
	var metadataURL string
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth-client.json" {
			t.Fatalf("metadata path = %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"client_id":                             metadataURL,
			"client_name":                           "Chat Client",
			"redirect_uris":                         []string{redirectURI},
			"grant_types":                           []string{"authorization_code", "refresh_token"},
			"response_types":                        []string{"code"},
			"token_endpoint_auth_method":            "private_key_jwt",
			"token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"},
			"token_endpoint_auth_signing_alg":       "RS256",
			"jwks_uri":                              "https://client.example/oauth/jwks.json",
			"logo_uri":                              "https://client.example/logo.png",
		})
	}))
	t.Cleanup(metadataServer.Close)
	metadataURL = metadataServer.URL + "/oauth-client.json"
	metadataClient := metadataServer.Client()
	metadataClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	var created hydraClient
	var adminGets atomic.Int32
	admin := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			adminGets.Add(1)
			writer.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			if request.URL.Path != "/admin/clients" {
				t.Fatalf("Hydra Admin create path = %s", request.URL.Path)
			}
			decodeJSONBody(t, request.Body, &created)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(created)
		default:
			t.Fatalf("unexpected Hydra Admin method %s", request.Method)
		}
	})
	var publicCalls atomic.Int32
	public := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		publicCalls.Add(1)
		if request.URL.Query().Get("client_id") != metadataURL || request.URL.Query().Get("audience") != testContract.ResourceURL {
			t.Fatalf("Hydra authorization query = %#v", request.URL.Query())
		}
		writer.Header().Set("Location", testContract.SiteOrigin+"/login")
		writer.WriteHeader(http.StatusFound)
	})
	handler := newTestHandler(t, public, admin, metadataClient)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response := getWithoutRedirect(t, authorizationURL(server.URL, metadataURL, redirectURI))
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("CIMD authorization status = %d", response.StatusCode)
	}
	if created.ID != metadataURL || created.Name != "Chat Client" || created.TokenEndpointAuthMethod != "private_key_jwt" || created.SkipConsent {
		t.Fatalf("created Hydra client = %#v", created)
	}
	if created.TokenEndpointAuthSigningAlg != "RS256" || created.JSONWebKeysURI != "https://client.example/oauth/jwks.json" ||
		created.LogoURI != "" || created.Scope != hydraClientScope || !slicesEqual(created.Audience, []string{testContract.ResourceURL}) {
		t.Fatalf("created Hydra client policy fields = %#v", created)
	}
	if !sameStringSet(created.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("created Hydra client grant types = %#v", created.GrantTypes)
	}
	if !isManagedCIMDClient(created) {
		t.Fatalf("created Hydra client marker = %s", created.Metadata)
	}
	if adminGets.Load() != 1 || publicCalls.Load() != 1 {
		t.Fatalf("Hydra calls: admin GET=%d public=%d", adminGets.Load(), publicCalls.Load())
	}
}

func TestCIMDRejectsRedirectMismatchBeforeHydra(t *testing.T) {
	t.Parallel()
	var metadataURL string
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"client_id":                  metadataURL,
			"client_name":                "CIMD Client",
			"redirect_uris":              []string{"https://client.example/expected"},
			"token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(metadataServer.Close)
	metadataURL = metadataServer.URL + "/client.json"
	metadataClient := metadataServer.Client()
	metadataClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var hydraCalls atomic.Int32
	handler := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hydraCalls.Add(1)
	}), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hydraCalls.Add(1)
	}), metadataClient)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response := getWithoutRedirect(t, authorizationURL(server.URL, metadataURL, "https://client.example/other"))
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("redirect mismatch status = %d", response.StatusCode)
	}
	if hydraCalls.Load() != 0 {
		t.Fatalf("redirect mismatch reached Hydra %d times", hydraCalls.Load())
	}
}

func TestCIMDNeverOverwritesUnmanagedHydraClient(t *testing.T) {
	t.Parallel()
	redirectURI := "https://client.example/callback"
	var metadataURL string
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"client_id":                  metadataURL,
			"client_name":                "CIMD Client",
			"redirect_uris":              []string{redirectURI},
			"token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(metadataServer.Close)
	metadataURL = metadataServer.URL + "/client.json"
	metadataClient := metadataServer.Client()
	metadataClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var writes atomic.Int32
	admin := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writes.Add(1)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(hydraClient{
			ID:                      metadataURL,
			Name:                    "Static Client",
			RedirectURIs:            []string{redirectURI},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			Scope:                   Scope,
			Audience:                []string{testContract.ResourceURL},
			TokenEndpointAuthMethod: "none",
		})
	})
	var publicCalls atomic.Int32
	handler := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		publicCalls.Add(1)
	}), admin, metadataClient)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response := getWithoutRedirect(t, authorizationURL(server.URL, metadataURL, redirectURI))
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("unmanaged conflict status = %d", response.StatusCode)
	}
	if writes.Load() != 0 || publicCalls.Load() != 0 {
		t.Fatalf("unmanaged client was modified: writes=%d public=%d", writes.Load(), publicCalls.Load())
	}
}

func TestFacadeRejectsOAuthDowngradesAndUnsafeRegistrationBeforeHydra(t *testing.T) {
	t.Parallel()
	var hydraCalls atomic.Int32
	hydra := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hydraCalls.Add(1)
	})
	handler := newTestHandler(t, hydra, hydra, rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	authorizationCases := []struct {
		name   string
		mutate func(url.Values)
	}{
		{name: "missing resource", mutate: func(query url.Values) { query.Del("resource") }},
		{name: "multiple resource", mutate: func(query url.Values) { query.Add("resource", testContract.ResourceURL) }},
		{name: "wrong resource", mutate: func(query url.Values) { query.Set("resource", testContract.SiteOrigin+"/other") }},
		{name: "plain PKCE", mutate: func(query url.Values) { query.Set("code_challenge_method", "plain") }},
		{name: "caller audience", mutate: func(query url.Values) { query.Set("audience", testContract.ResourceURL) }},
		{name: "request object", mutate: func(query url.Values) { query.Set("request", "unsigned-request") }},
		{name: "write scope", mutate: func(query url.Values) { query.Set("scope", "mcp:write") }},
	}
	for _, test := range authorizationCases {
		t.Run("authorization "+test.name, func(t *testing.T) {
			parsed, _ := url.Parse(authorizationURL(server.URL, "static-client", "https://client.example/callback"))
			query := parsed.Query()
			test.mutate(query)
			parsed.RawQuery = query.Encode()
			response := getWithoutRedirect(t, parsed.String())
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}

	tokenCases := []struct {
		name   string
		mutate func(url.Values)
	}{
		{name: "missing resource", mutate: func(form url.Values) { form.Del("resource") }},
		{name: "caller audience", mutate: func(form url.Values) { form.Set("audience", testContract.ResourceURL) }},
		{name: "short verifier", mutate: func(form url.Values) { form.Set("code_verifier", "short") }},
		{name: "client credentials", mutate: func(form url.Values) { form.Set("grant_type", "client_credentials") }},
		{name: "refresh without token", mutate: func(form url.Values) { form.Set("grant_type", "refresh_token") }},
	}
	for _, test := range tokenCases {
		t.Run("token "+test.name, func(t *testing.T) {
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"code"},
				"code_verifier": {testPKCEVerifier},
				"resource":      {testContract.ResourceURL},
			}
			test.mutate(form)
			request, _ := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}

	registrationCases := []struct {
		name string
		body map[string]any
	}{
		{name: "chosen client id", body: map[string]any{"client_id": "chosen", "client_name": "Client", "redirect_uris": []string{"https://client.example/callback"}}},
		{name: "client secret", body: map[string]any{"client_secret": "forbidden", "client_name": "Client", "redirect_uris": []string{"https://client.example/callback"}}},
		{name: "skip consent", body: map[string]any{"skip_consent": true, "client_name": "Client", "redirect_uris": []string{"https://client.example/callback"}}},
		{name: "public HTTP redirect", body: map[string]any{"client_name": "Client", "redirect_uris": []string{"http://client.example/callback"}}},
	}
	for _, test := range registrationCases {
		t.Run("registration "+test.name, func(t *testing.T) {
			response := postJSON(t, server.URL+"/oauth2/register", test.body)
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}
	if hydraCalls.Load() != 0 {
		t.Fatalf("invalid protocol input reached Hydra %d times", hydraCalls.Load())
	}
}

func TestAuthorizationContinuationProxiesOnlyExactHydraVerifier(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	hydra := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/oauth2/auth" || request.URL.Query().Get("audience") != testContract.ResourceURL {
			t.Fatalf("continuation request = %s", request.URL.String())
		}
		writer.Header().Set("Location", "https://client.example/callback?code=opaque")
		writer.WriteHeader(http.StatusFound)
	})
	handler := newTestHandler(t, hydra, hydra, rejectingHTTPClient())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	for _, verifierName := range []string{"login_verifier", "consent_verifier"} {
		parsed, err := url.Parse(authorizationURL(server.URL, "static-client", "https://client.example/callback"))
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		query.Set("audience", testContract.ResourceURL)
		query.Set(verifierName, "opaque-verifier")
		parsed.RawQuery = query.Encode()
		response := getWithoutRedirect(t, parsed.String())
		response.Body.Close()
		if response.StatusCode != http.StatusFound {
			t.Fatalf("%s continuation status = %d", verifierName, response.StatusCode)
		}
	}
	for _, mutate := range []func(url.Values){
		func(query url.Values) { query["login_verifier"] = []string{""} },
		func(query url.Values) { query["login_verifier"] = []string{"one", "two"} },
		func(query url.Values) { query.Set("consent_verifier", "two") },
		func(query url.Values) { query.Del("audience") },
		func(query url.Values) { query.Set("audience", testContract.SiteOrigin+"/other") },
	} {
		parsed, err := url.Parse(authorizationURL(server.URL, "static-client", "https://client.example/callback"))
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		query.Set("audience", testContract.ResourceURL)
		query.Set("login_verifier", "one")
		mutate(query)
		parsed.RawQuery = query.Encode()
		response := getWithoutRedirect(t, parsed.String())
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid continuation status = %d", response.StatusCode)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("Hydra continuation calls = %d, want 2", calls.Load())
	}
}

func newTestHandler(t *testing.T, publicHandler, adminHandler http.Handler, metadataClient *http.Client) *Handler {
	t.Helper()
	publicServer := httptest.NewServer(publicHandler)
	t.Cleanup(publicServer.Close)
	adminServer := httptest.NewServer(adminHandler)
	t.Cleanup(adminServer.Close)
	resolver, err := NewMetadataResolver(metadataClient)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewHydraClientManager(adminServer.URL, adminServer.Client(), testContract)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{
		Contract:          testContract,
		HydraPublicURL:    publicServer.URL,
		HydraPublicClient: publicServer.Client(),
		MetadataResolver:  resolver,
		HydraClients:      manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func rejectingHTTPClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func authorizationURL(baseURL, clientID, redirectURI string) string {
	query := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {Scope},
		"resource":              {testContract.ResourceURL},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state-value"},
	}
	return baseURL + "/oauth2/auth?" + query.Encode()
}

func getWithoutRedirect(t *testing.T, target string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func getJSON(t *testing.T, target string) map[string]any {
	t.Helper()
	response, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", target, response.StatusCode)
	}
	var result map[string]any
	decodeJSONBody(t, response.Body, &result)
	return result
}

func postJSON(t *testing.T, target string, value any) *http.Response {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(target, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeJSONBody(t *testing.T, reader io.Reader, target any) {
	t.Helper()
	if err := json.NewDecoder(reader).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("value is not a JSON array: %#v", value)
	}
	result := make([]string, len(values))
	for index, item := range values {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("array item is not a string: %#v", item)
		}
		result[index] = text
	}
	return result
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
