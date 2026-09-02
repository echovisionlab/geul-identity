package mcpoauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHydraV262RuntimeCompatibility(t *testing.T) {
	hydraPublicURL := os.Getenv("TEST_HYDRA_PUBLIC_URL")
	hydraAdminURL := os.Getenv("TEST_HYDRA_ADMIN_URL")
	if hydraPublicURL == "" && hydraAdminURL == "" {
		t.Skip("real Hydra runtime URLs are not configured")
	}
	if hydraPublicURL == "" || hydraAdminURL == "" {
		t.Fatal("TEST_HYDRA_PUBLIC_URL and TEST_HYDRA_ADMIN_URL must be set together")
	}

	redirectURI := "https://client.example/callback"
	signedRedirectURI := "https://signed-client.example/callback"
	metadataURL := "https://client.example/client.json"
	signedMetadataURL := "https://signed-client.example/signed-client.json"
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/client.json" && request.URL.Path != "/signed-client.json" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "max-age=300")
		if request.URL.Path == "/signed-client.json" {
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"client_id":                             signedMetadataURL,
				"client_name":                           "Runtime Signed CIMD Client",
				"redirect_uris":                         []string{signedRedirectURI},
				"grant_types":                           []string{"authorization_code", "refresh_token"},
				"response_types":                        []string{"code"},
				"token_endpoint_auth_method":            "private_key_jwt",
				"token_endpoint_auth_signing_alg":       "RS256",
				"jwks_uri":                              "https://signed-client.example/jwks.json",
				"token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"},
			})
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"client_id":                  metadataURL,
			"client_name":                "Runtime CIMD Client",
			"redirect_uris":              []string{redirectURI},
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
			"scope":                      Scope,
		})
	}))
	t.Cleanup(metadataServer.Close)
	metadataServerURL, err := url.Parse(metadataServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	metadataTransport := metadataServer.Client().Transport
	metadataClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		rewritten := request.Clone(request.Context())
		rewritten.URL.Scheme = metadataServerURL.Scheme
		rewritten.URL.Host = metadataServerURL.Host
		return metadataTransport.RoundTrip(rewritten)
	})}

	resolver, err := NewMetadataResolver(metadataClient)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewHydraClientManager(hydraAdminURL, &http.Client{}, testContract)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{
		Contract:          testContract,
		HydraPublicURL:    hydraPublicURL,
		HydraPublicClient: &http.Client{},
		MetadataResolver:  resolver,
		HydraClients:      manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	facade := httptest.NewServer(handler)
	t.Cleanup(facade.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	dcrResponse := postJSON(t, facade.URL+"/oauth2/register", map[string]any{
		"client_name":                "Runtime DCR Client",
		"redirect_uris":              []string{"http://127.0.0.1:49152/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      hydraClientScope,
	})
	defer dcrResponse.Body.Close()
	if dcrResponse.StatusCode != http.StatusCreated {
		t.Fatalf("real Hydra DCR status = %d", dcrResponse.StatusCode)
	}
	var registration map[string]any
	decodeJSONBody(t, dcrResponse.Body, &registration)
	dcrClientID, ok := registration["client_id"].(string)
	if !ok || !dynamicClientIDPattern.MatchString(dcrClientID) {
		t.Fatalf("real Hydra DCR returned an invalid client_id type or shape")
	}
	if registration["registration_client_uri"] != testContract.IssuerURL+"/oauth2/register/"+url.PathEscape(dcrClientID) {
		t.Fatal("real Hydra DCR management URI did not stay on the facade issuer")
	}
	dcrClient := readHydraClient(t, hydraAdminURL, dcrClientID)
	if dcrClient.Scope != hydraClientScope || !slicesEqual(dcrClient.Audience, []string{testContract.ResourceURL}) ||
		dcrClient.TokenEndpointAuthMethod != "none" || dcrClient.SkipConsent {
		t.Fatalf("real Hydra DCR client profile is not the normalized MCP profile")
	}

	authorizeResponse := getWithClient(t, browser, authorizationURL(facade.URL, metadataURL, redirectURI))
	if authorizeResponse.StatusCode != http.StatusFound {
		authorizeResponse.Body.Close()
		t.Fatalf("real Hydra CIMD authorization status = %d", authorizeResponse.StatusCode)
	}
	loginLocation := authorizeResponse.Header.Get("Location")
	authorizeResponse.Body.Close()
	if !strings.HasPrefix(loginLocation, testContract.SiteOrigin+"/login?") {
		t.Fatalf("real Hydra authorization login redirect = %q", loginLocation)
	}
	cimdClient := readHydraClient(t, hydraAdminURL, metadataURL)
	if cimdClient.Name != "Runtime CIMD Client" || !isManagedCIMDClient(cimdClient) ||
		!slicesEqual(cimdClient.Audience, []string{testContract.ResourceURL}) || cimdClient.SkipConsent {
		t.Fatalf("real Hydra CIMD client is not facade-managed with the MCP profile")
	}

	signedJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	signedBrowser := &http.Client{
		Jar: signedJar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	signedAuthorizeURL := authorizationURL(facade.URL, signedMetadataURL, signedRedirectURI)
	parsedSignedAuthorizeURL, err := url.Parse(signedAuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	signedAuthorizeQuery := parsedSignedAuthorizeURL.Query()
	signedAuthorizeQuery.Set("scope", hydraClientScope)
	parsedSignedAuthorizeURL.RawQuery = signedAuthorizeQuery.Encode()
	signedAuthorizeResponse := getWithClient(t, signedBrowser, parsedSignedAuthorizeURL.String())
	if signedAuthorizeResponse.StatusCode != http.StatusFound {
		var protocolError map[string]string
		_ = json.NewDecoder(signedAuthorizeResponse.Body).Decode(&protocolError)
		signedAuthorizeResponse.Body.Close()
		t.Fatalf("real Hydra signed CIMD authorization status = %d, error = %q, description = %q",
			signedAuthorizeResponse.StatusCode, protocolError["error"], protocolError["error_description"])
	}
	signedLoginLocation := signedAuthorizeResponse.Header.Get("Location")
	signedAuthorizeResponse.Body.Close()
	if !strings.HasPrefix(signedLoginLocation, testContract.SiteOrigin+"/login?") {
		t.Fatalf("real Hydra signed authorization login redirect = %q", signedLoginLocation)
	}
	signedCIMDClient := readHydraClient(t, hydraAdminURL, signedMetadataURL)
	if signedCIMDClient.Name != "Runtime Signed CIMD Client" || !isManagedCIMDClient(signedCIMDClient) ||
		signedCIMDClient.TokenEndpointAuthMethod != "private_key_jwt" ||
		signedCIMDClient.TokenEndpointAuthSigningAlg != "RS256" ||
		signedCIMDClient.JSONWebKeysURI != "https://signed-client.example/jwks.json" ||
		!sameStringSet(signedCIMDClient.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
		!slicesEqual(signedCIMDClient.Audience, []string{testContract.ResourceURL}) || signedCIMDClient.SkipConsent {
		t.Fatalf("real Hydra signed CIMD client is not facade-managed with the signed MCP profile")
	}
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const signingKeyID = "runtime-cimd-key"
	replaceHydraClientJWKS(t, hydraAdminURL, signedMetadataURL, &signingKey.PublicKey, signingKeyID)

	authorizationCode := completeHydraAuthorization(t, hydraAdminURL, facade.URL, browser, loginLocation, redirectURI, []string{Scope})

	tokenResponse := postForm(t, facade.URL+"/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {metadataURL},
		"code":          {authorizationCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {testPKCEVerifier},
		"resource":      {testContract.ResourceURL},
	})
	if tokenResponse.StatusCode != http.StatusOK {
		tokenResponse.Body.Close()
		t.Fatalf("real Hydra token exchange status = %d", tokenResponse.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
	}
	decodeJSONBody(t, tokenResponse.Body, &token)
	tokenResponse.Body.Close()
	if token.AccessToken == "" || token.Scope != Scope || !strings.EqualFold(token.TokenType, "bearer") {
		t.Fatalf("real Hydra token response is missing the normalized MCP grant: access=%t scope=%q type=%q",
			token.AccessToken != "", token.Scope, token.TokenType)
	}

	introspection := introspectHydraToken(t, hydraAdminURL, token.AccessToken)
	if !introspection.Active || introspection.ClientID != metadataURL || introspection.Scope != Scope ||
		!slicesEqual(introspection.Audience, []string{testContract.ResourceURL}) {
		t.Fatal("real Hydra access token is not active and bound to the exact MCP resource")
	}
	revokeResponse := postForm(t, facade.URL+"/oauth2/revoke", url.Values{
		"client_id": {metadataURL},
		"token":     {token.AccessToken},
	})
	io.Copy(io.Discard, revokeResponse.Body)
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK {
		t.Fatalf("real Hydra revocation status = %d", revokeResponse.StatusCode)
	}
	if introspectHydraToken(t, hydraAdminURL, token.AccessToken).Active {
		t.Fatal("real Hydra access token remained active after facade revocation")
	}

	signedAuthorizationCode := completeHydraAuthorization(
		t, hydraAdminURL, facade.URL, signedBrowser, signedLoginLocation, signedRedirectURI,
		[]string{Scope, OfflineAccessScope},
	)
	clientAssertion := signClientAssertion(t, signingKey, signingKeyID, signedMetadataURL, testContract.IssuerURL+"/oauth2/token")
	signedTokenResponse := postForm(t, facade.URL+"/oauth2/token", url.Values{
		"grant_type":            {"authorization_code"},
		"client_id":             {signedMetadataURL},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
		"code":                  {signedAuthorizationCode},
		"redirect_uri":          {signedRedirectURI},
		"code_verifier":         {testPKCEVerifier},
		"resource":              {testContract.ResourceURL},
	})
	if signedTokenResponse.StatusCode != http.StatusOK {
		var protocolError map[string]string
		_ = json.NewDecoder(signedTokenResponse.Body).Decode(&protocolError)
		signedTokenResponse.Body.Close()
		t.Fatalf("real Hydra signed token exchange status = %d, error = %q, description = %q",
			signedTokenResponse.StatusCode, protocolError["error"], protocolError["error_description"])
	}
	var signedToken struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	decodeJSONBody(t, signedTokenResponse.Body, &signedToken)
	signedTokenResponse.Body.Close()
	if signedToken.AccessToken == "" || signedToken.RefreshToken == "" ||
		!sameStringSet(strings.Fields(signedToken.Scope), []string{Scope, OfflineAccessScope}) ||
		!strings.EqualFold(signedToken.TokenType, "bearer") {
		t.Fatalf("real Hydra signed token response is missing the normalized MCP refresh grant: access=%t refresh=%t scope=%q type=%q",
			signedToken.AccessToken != "", signedToken.RefreshToken != "", signedToken.Scope, signedToken.TokenType)
	}
	signedIntrospection := introspectHydraToken(t, hydraAdminURL, signedToken.AccessToken)
	if !signedIntrospection.Active || signedIntrospection.ClientID != signedMetadataURL ||
		!sameStringSet(strings.Fields(signedIntrospection.Scope), []string{Scope, OfflineAccessScope}) ||
		!slicesEqual(signedIntrospection.Audience, []string{testContract.ResourceURL}) {
		t.Fatal("real Hydra signed access token is not active and bound to the exact MCP resource")
	}
	refreshAssertion := signClientAssertion(t, signingKey, signingKeyID, signedMetadataURL, testContract.IssuerURL+"/oauth2/token")
	refreshResponse := postForm(t, facade.URL+"/oauth2/token", url.Values{
		"grant_type":            {"refresh_token"},
		"client_id":             {signedMetadataURL},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {refreshAssertion},
		"refresh_token":         {signedToken.RefreshToken},
		"resource":              {testContract.ResourceURL},
	})
	if refreshResponse.StatusCode != http.StatusOK {
		var protocolError map[string]string
		_ = json.NewDecoder(refreshResponse.Body).Decode(&protocolError)
		refreshResponse.Body.Close()
		t.Fatalf("real Hydra refresh status = %d, error = %q, description = %q",
			refreshResponse.StatusCode, protocolError["error"], protocolError["error_description"])
	}
	var refreshedToken struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	decodeJSONBody(t, refreshResponse.Body, &refreshedToken)
	refreshResponse.Body.Close()
	if refreshedToken.AccessToken == "" || refreshedToken.RefreshToken == "" ||
		refreshedToken.RefreshToken == signedToken.RefreshToken ||
		!sameStringSet(strings.Fields(refreshedToken.Scope), []string{Scope, OfflineAccessScope}) {
		t.Fatalf("real Hydra refresh did not rotate the token pair")
	}
	refreshedIntrospection := introspectHydraToken(t, hydraAdminURL, refreshedToken.AccessToken)
	if !refreshedIntrospection.Active || refreshedIntrospection.ClientID != signedMetadataURL ||
		!sameStringSet(strings.Fields(refreshedIntrospection.Scope), []string{Scope, OfflineAccessScope}) ||
		!slicesEqual(refreshedIntrospection.Audience, []string{testContract.ResourceURL}) {
		t.Fatal("refreshed access token is not active and bound to the exact MCP resource")
	}
}

func completeHydraAuthorization(
	t *testing.T,
	hydraAdminURL string,
	facadeURL string,
	browser *http.Client,
	loginLocation string,
	redirectURI string,
	grantScopes []string,
) string {
	t.Helper()
	loginChallenge := requiredQueryValue(t, loginLocation, "login_challenge")
	loginRedirect := acceptHydraRequest(t, hydraAdminURL,
		"/admin/oauth2/auth/requests/login/accept", "login_challenge", loginChallenge,
		map[string]any{"subject": "identity-1", "remember": false},
	)
	consentResponse := getWithClient(t, browser, routeThroughFacade(t, facadeURL, loginRedirect))
	if consentResponse.StatusCode != http.StatusFound {
		var protocolError map[string]string
		_ = json.NewDecoder(consentResponse.Body).Decode(&protocolError)
		consentResponse.Body.Close()
		t.Fatalf("real Hydra login continuation status = %d, parameters = %v, error = %s", consentResponse.StatusCode,
			queryParameterNames(t, loginRedirect), protocolError["error"])
	}
	consentLocation := consentResponse.Header.Get("Location")
	consentResponse.Body.Close()
	consentURL, err := url.Parse(consentLocation)
	if err != nil {
		t.Fatal(err)
	}
	if consentURL.Scheme+"://"+consentURL.Host != testContract.SiteOrigin || consentURL.Path != "/consent" {
		t.Fatalf("real Hydra login continuation did not reach configured consent: scheme=%q host=%q path=%q parameters=%v error=%q description=%q",
			consentURL.Scheme, consentURL.Host, consentURL.Path, queryParameterNames(t, consentLocation),
			consentURL.Query().Get("error"), consentURL.Query().Get("error_description"))
	}

	consentChallenge := requiredQueryValue(t, consentLocation, "consent_challenge")
	consentRedirect := acceptHydraRequest(t, hydraAdminURL,
		"/admin/oauth2/auth/requests/consent/accept", "consent_challenge", consentChallenge,
		map[string]any{
			"grant_scope":                 grantScopes,
			"grant_access_token_audience": []string{testContract.ResourceURL},
			"remember":                    false,
		},
	)
	clientResponse := getWithClient(t, browser, routeThroughFacade(t, facadeURL, consentRedirect))
	if clientResponse.StatusCode != http.StatusSeeOther {
		clientResponse.Body.Close()
		t.Fatalf("real Hydra consent continuation status = %d", clientResponse.StatusCode)
	}
	clientLocation := clientResponse.Header.Get("Location")
	clientResponse.Body.Close()
	if parsed, err := url.Parse(clientLocation); err != nil || parsed.Scheme+"://"+parsed.Host+parsed.Path != redirectURI ||
		parsed.Query().Get("state") != "state-value" {
		t.Fatalf("real Hydra authorization did not return the exact client redirect and state")
	}
	return requiredQueryValue(t, clientLocation, "code")
}

func replaceHydraClientJWKS(t *testing.T, hydraAdminURL, clientID string, publicKey *rsa.PublicKey, keyID string) {
	t.Helper()
	endpoint := strings.TrimRight(hydraAdminURL, "/") + "/admin/clients/" + url.PathEscape(clientID)
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("Hydra Admin client lookup status = %d", response.StatusCode)
	}
	var client map[string]any
	decodeJSONBody(t, response.Body, &client)
	response.Body.Close()
	delete(client, "jwks_uri")
	client["jwks"] = map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": keyID,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}}}
	body, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Hydra Admin client JWKS update status = %d", response.StatusCode)
	}
}

func signClientAssertion(t *testing.T, privateKey *rsa.PrivateKey, keyID, clientID, audience string) string {
	t.Helper()
	now := time.Now().UTC()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": "hydra-runtime-" + now.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func acceptHydraRequest(t *testing.T, hydraAdminURL, path, challengeName, challenge string, decision map[string]any) string {
	t.Helper()
	body, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimRight(hydraAdminURL, "/") + path + "?" + url.Values{challengeName: {challenge}}.Encode()
	request, err := http.NewRequest(http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Hydra Admin decision status = %d", response.StatusCode)
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	decodeJSONBody(t, response.Body, &result)
	if result.RedirectTo == "" {
		t.Fatal("Hydra Admin decision omitted redirect_to")
	}
	return result.RedirectTo
}

func requiredQueryValue(t *testing.T, target, name string) string {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	values := parsed.Query()[name]
	if len(values) != 1 || values[0] == "" {
		t.Fatalf("OAuth redirect omitted exactly one %s", name)
	}
	return values[0]
}

func queryParameterNames(t *testing.T, target string) []string {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(parsed.Query()))
	for name := range parsed.Query() {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func routeThroughFacade(t *testing.T, facadeURL, hydraRedirect string) string {
	t.Helper()
	facade, err := url.Parse(facadeURL)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(hydraRedirect)
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Scheme+"://"+redirect.Host != testContract.IssuerURL || redirect.Path != "/oauth2/auth" {
		t.Fatal("Hydra continuation redirect escaped the configured public authorization endpoint")
	}
	redirect.Scheme = facade.Scheme
	redirect.Host = facade.Host
	return redirect.String()
}

func postForm(t *testing.T, target string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func getWithClient(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type hydraIntrospection struct {
	Active   bool     `json:"active"`
	Audience []string `json:"aud"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
}

func introspectHydraToken(t *testing.T, hydraAdminURL, token string) hydraIntrospection {
	t.Helper()
	response := postForm(t, strings.TrimRight(hydraAdminURL, "/")+"/admin/oauth2/introspect", url.Values{"token": {token}})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Hydra Admin introspection status = %d", response.StatusCode)
	}
	var result hydraIntrospection
	decodeJSONBody(t, response.Body, &result)
	return result
}

func readHydraClient(t *testing.T, hydraAdminURL, clientID string) hydraClient {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(hydraAdminURL, "/")+"/admin/clients/"+url.PathEscape(clientID), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Hydra Admin client lookup status = %d", response.StatusCode)
	}
	var client hydraClient
	decodeJSONBody(t, response.Body, &client)
	return client
}
