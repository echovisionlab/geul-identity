package mcpoauth

import (
	"slices"
	"strings"
	"testing"
)

func TestClientIDMetadataURLValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: "https://client.example/oauth/client.json"},
		{name: "valid explicit port", value: "https://client.example:8443/oauth/client.json"},
		{name: "HTTP", value: "http://client.example/client.json", wantErr: true},
		{name: "root path", value: "https://client.example/", wantErr: true},
		{name: "missing path", value: "https://client.example", wantErr: true},
		{name: "query", value: "https://client.example/client.json?v=1", wantErr: true},
		{name: "fragment", value: "https://client.example/client.json#metadata", wantErr: true},
		{name: "credentials", value: "https://user@client.example/client.json", wantErr: true},
		{name: "dot segment", value: "https://client.example/oauth/../client.json", wantErr: true},
		{name: "encoded dot segment", value: "https://client.example/oauth/%2e%2e/client.json", wantErr: true},
		{name: "too long", value: "https://client.example/" + strings.Repeat("a", maxOAuthURIBytes), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateClientIDURL(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateClientIDURL(%q) error = %v, wantErr=%t", test.value, err, test.wantErr)
			}
		})
	}
}

func TestRedirectURIValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "HTTPS", value: "https://client.example/callback"},
		{name: "IPv4 loopback", value: "http://127.0.0.1:49152/callback"},
		{name: "IPv6 loopback", value: "http://[::1]:49152/callback"},
		{name: "localhost", value: "http://localhost:49152/callback"},
		{name: "public HTTP", value: "http://client.example/callback", wantErr: true},
		{name: "loopback without port", value: "http://127.0.0.1/callback", wantErr: true},
		{name: "fragment", value: "https://client.example/callback#fragment", wantErr: true},
		{name: "credentials", value: "https://user@client.example/callback", wantErr: true},
		{name: "custom scheme", value: "client-app://callback", wantErr: true},
		{name: "relative", value: "/callback", wantErr: true},
		{name: "too long", value: "https://client.example/" + strings.Repeat("a", maxOAuthURIBytes), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURI(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateRedirectURI(%q) error = %v, wantErr=%t", test.value, err, test.wantErr)
			}
		})
	}
}

func TestDynamicMetadataNormalizesMCPAuthorizationAndRefreshProfile(t *testing.T) {
	t.Parallel()
	metadata, err := normalizeClientMetadata(clientMetadata{
		ClientName:              "MCP Client",
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   Scope,
		LogoURI:                 "https://client.example/logo.png",
		ClientURI:               "https://client.example/",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.GrantTypes) != 1 || metadata.GrantTypes[0] != "authorization_code" {
		t.Fatalf("grant types = %#v", metadata.GrantTypes)
	}
	if metadata.LogoURI != "" || metadata.ClientURI != "" {
		t.Fatalf("remote presentation metadata was retained: %#v", metadata)
	}
	refreshMetadata, err := normalizeClientMetadata(clientMetadata{
		ClientName:              "MCP Client",
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   hydraClientScope,
	}, false)
	if err != nil || !sameStringSet(refreshMetadata.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
		refreshMetadata.Scope != hydraClientScope {
		t.Fatalf("refresh metadata = %#v, error = %v", refreshMetadata, err)
	}

	invalid := []clientMetadata{
		{ClientName: "MCP Client", RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"client_credentials"}},
		{ClientName: "MCP Client", RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"authorization_code", "client_credentials"}},
		{ClientName: "MCP Client", RedirectURIs: []string{"https://client.example/callback"}, ResponseTypes: []string{"token"}},
		{ClientName: "MCP Client", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: "client_secret_basic"},
		{ClientName: "MCP Client", RedirectURIs: []string{"https://client.example/callback"}, Scope: "mcp:write"},
		{ClientName: " MCP Client", RedirectURIs: []string{"https://client.example/callback"}},
	}
	for _, candidate := range invalid {
		if _, err := normalizeClientMetadata(candidate, false); err == nil {
			t.Fatalf("invalid metadata accepted: %#v", candidate)
		}
	}
}

func TestCIMDMetadataAcceptsSignedChatClientRefreshProfile(t *testing.T) {
	t.Parallel()
	metadata, err := normalizeClientMetadata(clientMetadata{
		ClientID:                          "https://client.example/oauth/client.json",
		ClientName:                        "Chat Client",
		RedirectURIs:                      []string{"https://client.example/oauth/callback"},
		GrantTypes:                        []string{"authorization_code", "refresh_token"},
		ResponseTypes:                     []string{"code"},
		TokenEndpointAuthMethod:           "private_key_jwt",
		TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
		TokenEndpointAuthAlg:              "RS256",
		JSONWebKeysURI:                    "https://client.example/oauth/jwks.json",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !sameStringSet(metadata.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
		metadata.TokenEndpointAuthMethod != "private_key_jwt" || metadata.TokenEndpointAuthAlg != "RS256" ||
		metadata.JSONWebKeysURI != "https://client.example/oauth/jwks.json" {
		t.Fatalf("normalized signed CIMD metadata = %#v", metadata)
	}

	invalid := []clientMetadata{
		{ClientID: "https://client.example/client.json", ClientName: "Client", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: "private_key_jwt", JSONWebKeysURI: "https://client.example/jwks.json"},
		{ClientID: "https://client.example/client.json", ClientName: "Client", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthAlg: "RS256"},
		{ClientID: "https://client.example/client.json", ClientName: "Client", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthAlg: "ES256", JSONWebKeysURI: "https://client.example/jwks.json"},
		{ClientID: "https://client.example/client.json", ClientName: "Client", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthAlg: "RS256", JSONWebKeysURI: "http://client.example/jwks.json"},
	}
	for _, candidate := range invalid {
		if _, err := normalizeClientMetadata(candidate, true); err == nil {
			t.Fatalf("invalid signed CIMD metadata accepted: %#v", candidate)
		}
	}
}

func TestCIMDTokenEndpointAuthenticationNegotiation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		singular string
		plural   []string
		want     string
		wantErr  bool
	}{
		{name: "legacy preference wins", singular: "private_key_jwt", plural: []string{"none", "private_key_jwt"}, want: "private_key_jwt"},
		{name: "explicit public preference wins", singular: "none", plural: []string{"none", "private_key_jwt"}, want: "none"},
		{name: "unambiguous signed method", plural: []string{"private_key_jwt"}, want: "private_key_jwt"},
		{name: "unambiguous public method", plural: []string{"none"}, want: "none"},
		{name: "ambiguous without legacy preference", plural: []string{"none", "private_key_jwt"}, wantErr: true},
		{name: "singular must belong to array", singular: "private_key_jwt", plural: []string{"none"}, wantErr: true},
		{name: "symmetric client method forbidden", plural: []string{"none", "client_secret_basic"}, wantErr: true},
		{name: "no intersection", plural: []string{"tls_client_auth"}, wantErr: true},
		{name: "empty array", plural: []string{}, wantErr: true},
		{name: "duplicate method", plural: []string{"none", "none"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			metadata := clientMetadata{
				ClientID:                          "https://client.example/client.json",
				ClientName:                        "Client",
				RedirectURIs:                      []string{"https://client.example/callback"},
				TokenEndpointAuthMethod:           test.singular,
				TokenEndpointAuthMethodsSupported: test.plural,
			}
			if test.singular == "private_key_jwt" || slices.Contains(test.plural, "private_key_jwt") {
				metadata.TokenEndpointAuthAlg = "RS256"
				metadata.JSONWebKeysURI = "https://client.example/jwks.json"
			}
			normalized, err := normalizeClientMetadata(metadata, true)
			if (err != nil) != test.wantErr {
				t.Fatalf("normalizeClientMetadata() error = %v, wantErr=%t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if normalized.TokenEndpointAuthMethod != test.want {
				t.Fatalf("selected method = %q, want %q", normalized.TokenEndpointAuthMethod, test.want)
			}
			if test.want == "none" && (normalized.TokenEndpointAuthAlg != "" || normalized.JSONWebKeysURI != "") {
				t.Fatalf("public selection retained signing metadata: %#v", normalized)
			}
		})
	}
}

func TestDecodeClientMetadataRejectsNullTokenEndpointAuthMethodsSupported(t *testing.T) {
	t.Parallel()

	_, _, err := decodeClientMetadata([]byte(`{
		"client_id":"https://client.example/client.json",
		"client_name":"Client",
		"redirect_uris":["https://client.example/callback"],
		"token_endpoint_auth_methods_supported":null
	}`))
	if err == nil {
		t.Fatal("decodeClientMetadata() accepted a null token_endpoint_auth_methods_supported value")
	}
}
