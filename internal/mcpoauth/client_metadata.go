package mcpoauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxClientNameRunes = 200
	maxRedirectURIs    = 10
	maxOAuthURIBytes   = 2048
)

type clientMetadata struct {
	ClientID                          string   `json:"client_id,omitempty"`
	ClientName                        string   `json:"client_name"`
	RedirectURIs                      []string `json:"redirect_uris"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthAlg              string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	JSONWebKeysURI                    string   `json:"jwks_uri,omitempty"`
	Scope                             string   `json:"scope,omitempty"`
	LogoURI                           string   `json:"logo_uri,omitempty"`
	ClientURI                         string   `json:"client_uri,omitempty"`
	PolicyURI                         string   `json:"policy_uri,omitempty"`
	TermsOfServiceURI                 string   `json:"tos_uri,omitempty"`
	Contacts                          []string `json:"contacts,omitempty"`
	SoftwareID                        string   `json:"software_id,omitempty"`
	SoftwareVersion                   string   `json:"software_version,omitempty"`
}

var supportedClientMetadataFields = []string{
	"client_id",
	"client_name",
	"redirect_uris",
	"grant_types",
	"response_types",
	"token_endpoint_auth_method",
	"token_endpoint_auth_methods_supported",
	"token_endpoint_auth_signing_alg",
	"jwks_uri",
	"scope",
	"logo_uri",
	"client_uri",
	"policy_uri",
	"tos_uri",
	"contacts",
	"software_id",
	"software_version",
}

func decodeClientMetadata(body []byte) (clientMetadata, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil {
		return clientMetadata{}, nil, fmt.Errorf("decode client metadata: %w", err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return clientMetadata{}, nil, errors.New("client metadata must be a JSON object")
	}

	raw := make(map[string]json.RawMessage)
	for dec.More() {
		nameToken, err := dec.Token()
		if err != nil {
			return clientMetadata{}, nil, fmt.Errorf("decode client metadata field: %w", err)
		}
		name, ok := nameToken.(string)
		if !ok {
			return clientMetadata{}, nil, errors.New("client metadata field name is invalid")
		}
		if _, duplicate := raw[name]; duplicate {
			return clientMetadata{}, nil, fmt.Errorf("client metadata field %q is duplicated", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return clientMetadata{}, nil, fmt.Errorf("decode client metadata field %q: %w", name, err)
		}
		raw[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return clientMetadata{}, nil, fmt.Errorf("close client metadata object: %w", err)
	}
	if token, err := dec.Token(); err != io.EOF {
		if err != nil {
			return clientMetadata{}, nil, fmt.Errorf("decode trailing client metadata: %w", err)
		}
		return clientMetadata{}, nil, fmt.Errorf("unexpected trailing JSON token %v", token)
	}

	// Client metadata specifications allow extension properties. Keep the raw
	// map for explicit unsafe-field checks, but decode only the exact fields this
	// facade validates and deliberately propagates.
	if value, ok := raw["token_endpoint_auth_methods_supported"]; ok &&
		bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return clientMetadata{}, nil, errors.New("token_endpoint_auth_methods_supported must be an array")
	}
	supported := make(map[string]json.RawMessage, len(supportedClientMetadataFields))
	for _, name := range supportedClientMetadataFields {
		if value, ok := raw[name]; ok {
			supported[name] = value
		}
	}
	encoded, err := json.Marshal(supported)
	if err != nil {
		return clientMetadata{}, nil, fmt.Errorf("normalize client metadata: %w", err)
	}
	var metadata clientMetadata
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return clientMetadata{}, nil, fmt.Errorf("decode supported client metadata: %w", err)
	}
	return metadata, raw, nil
}

func normalizeClientMetadata(metadata clientMetadata, requireClientID bool) (clientMetadata, error) {
	if requireClientID && metadata.ClientID == "" {
		return clientMetadata{}, errors.New("client_id is required")
	}
	if metadata.ClientName == "" || strings.TrimSpace(metadata.ClientName) != metadata.ClientName {
		return clientMetadata{}, errors.New("client_name is required without leading or trailing whitespace")
	}
	if !utf8.ValidString(metadata.ClientName) || utf8.RuneCountInString(metadata.ClientName) > maxClientNameRunes {
		return clientMetadata{}, errors.New("client_name is invalid or too long")
	}
	for _, r := range metadata.ClientName {
		if unicode.IsControl(r) {
			return clientMetadata{}, errors.New("client_name contains a control character")
		}
	}

	if len(metadata.RedirectURIs) == 0 || len(metadata.RedirectURIs) > maxRedirectURIs {
		return clientMetadata{}, fmt.Errorf("redirect_uris must contain between 1 and %d values", maxRedirectURIs)
	}
	seenRedirects := make(map[string]struct{}, len(metadata.RedirectURIs))
	for _, redirectURI := range metadata.RedirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			return clientMetadata{}, fmt.Errorf("redirect_uri %q: %w", redirectURI, err)
		}
		if _, duplicate := seenRedirects[redirectURI]; duplicate {
			return clientMetadata{}, fmt.Errorf("redirect_uri %q is duplicated", redirectURI)
		}
		seenRedirects[redirectURI] = struct{}{}
	}

	if len(metadata.GrantTypes) == 0 {
		metadata.GrantTypes = []string{"authorization_code"}
	}
	if requireClientID {
		switch {
		case sameStringSet(metadata.GrantTypes, []string{"authorization_code"}):
			metadata.GrantTypes = []string{"authorization_code"}
		case sameStringSet(metadata.GrantTypes, []string{"authorization_code", "refresh_token"}):
			// A CIMD client may declare refresh support even when this authorization
			// server does not advertise or admit that grant. Preserve the declaration
			// in Hydra so client authentication metadata remains exact; the public
			// facade continues to reject refresh-token requests.
			metadata.GrantTypes = []string{"authorization_code", "refresh_token"}
		default:
			return clientMetadata{}, errors.New("grant_types must contain authorization_code and may additionally contain refresh_token")
		}
	} else {
		switch {
		case sameStringSet(metadata.GrantTypes, []string{"authorization_code"}):
			metadata.GrantTypes = []string{"authorization_code"}
		case sameStringSet(metadata.GrantTypes, []string{"authorization_code", "refresh_token"}):
			metadata.GrantTypes = []string{"authorization_code", "refresh_token"}
		default:
			return clientMetadata{}, errors.New("grant_types must contain authorization_code and may additionally contain refresh_token")
		}
	}

	if len(metadata.ResponseTypes) == 0 {
		metadata.ResponseTypes = []string{"code"}
	}
	if !sameStringSet(metadata.ResponseTypes, []string{"code"}) {
		return clientMetadata{}, errors.New("response_types must contain only code")
	}
	metadata.ResponseTypes = []string{"code"}

	clientSupportsPrivateKeyJWT := requireClientID && slices.Contains(metadata.TokenEndpointAuthMethodsSupported, "private_key_jwt")
	selectedAuthMethod, err := selectTokenEndpointAuthMethod(metadata, requireClientID)
	if err != nil {
		return clientMetadata{}, err
	}
	metadata.TokenEndpointAuthMethod = selectedAuthMethod
	metadata.TokenEndpointAuthMethodsSupported = nil
	switch metadata.TokenEndpointAuthMethod {
	case "none":
		if !clientSupportsPrivateKeyJWT &&
			(metadata.TokenEndpointAuthAlg != "" || metadata.JSONWebKeysURI != "") {
			return clientMetadata{}, errors.New("public clients cannot supply token endpoint signing metadata")
		}
		metadata.TokenEndpointAuthAlg = ""
		metadata.JSONWebKeysURI = ""
	case "private_key_jwt":
		if !requireClientID {
			return clientMetadata{}, errors.New("dynamic registration supports only public-client token authentication")
		}
		if metadata.TokenEndpointAuthAlg != "RS256" {
			return clientMetadata{}, errors.New("private_key_jwt requires token_endpoint_auth_signing_alg RS256")
		}
		if err := validateJSONWebKeysURI(metadata.JSONWebKeysURI); err != nil {
			return clientMetadata{}, err
		}
	default:
		return clientMetadata{}, errors.New("token_endpoint_auth_method must be none or private_key_jwt")
	}
	if metadata.Scope == "" {
		metadata.Scope = Scope
	}
	if scopes := strings.Fields(metadata.Scope); !sameStringSet(scopes, []string{Scope}) &&
		!sameStringSet(scopes, []string{Scope, OfflineAccessScope}) {
		return clientMetadata{}, fmt.Errorf("scope must be %q with optional %q", Scope, OfflineAccessScope)
	}

	// Remote presentation URIs are intentionally not propagated into Hydra.
	// Until an Identity-owned safe image fetch/cache is released, consent uses
	// the generic icon and only the validated client name.
	metadata.LogoURI = ""
	metadata.ClientURI = ""
	metadata.PolicyURI = ""
	metadata.TermsOfServiceURI = ""
	metadata.Contacts = nil
	metadata.SoftwareID = ""
	metadata.SoftwareVersion = ""
	return metadata, nil
}

func selectTokenEndpointAuthMethod(metadata clientMetadata, requireClientID bool) (string, error) {
	if !requireClientID || metadata.TokenEndpointAuthMethodsSupported == nil {
		if metadata.TokenEndpointAuthMethod == "" {
			return "none", nil
		}
		switch metadata.TokenEndpointAuthMethod {
		case "none", "private_key_jwt":
			return metadata.TokenEndpointAuthMethod, nil
		default:
			return "", errors.New("token_endpoint_auth_method must be none or private_key_jwt")
		}
	}
	if len(metadata.TokenEndpointAuthMethodsSupported) == 0 {
		return "", errors.New("token_endpoint_auth_methods_supported must contain at least one method")
	}

	intersection := make(map[string]struct{}, 2)
	seen := make(map[string]struct{}, len(metadata.TokenEndpointAuthMethodsSupported))
	for _, method := range metadata.TokenEndpointAuthMethodsSupported {
		if method == "" {
			return "", errors.New("token_endpoint_auth_methods_supported cannot contain an empty method")
		}
		if _, duplicate := seen[method]; duplicate {
			return "", fmt.Errorf("token_endpoint_auth_methods_supported contains duplicate method %q", method)
		}
		seen[method] = struct{}{}
		switch method {
		case "client_secret_basic", "client_secret_post", "client_secret_jwt":
			return "", fmt.Errorf("token_endpoint_auth_methods_supported cannot contain symmetric client method %q", method)
		}
		if method == "none" || method == "private_key_jwt" {
			intersection[method] = struct{}{}
		}
	}
	if metadata.TokenEndpointAuthMethod != "" {
		if _, declared := seen[metadata.TokenEndpointAuthMethod]; !declared {
			return "", errors.New("token_endpoint_auth_method must be a member of token_endpoint_auth_methods_supported")
		}
		if _, preferred := intersection[metadata.TokenEndpointAuthMethod]; preferred {
			return metadata.TokenEndpointAuthMethod, nil
		}
	}
	if len(intersection) == 0 {
		return "", errors.New("token_endpoint_auth_methods_supported has no method supported by this authorization server")
	}
	if len(intersection) > 1 {
		return "", errors.New("token_endpoint_auth_methods_supported is ambiguous without a mutually supported singular preference")
	}
	for method := range intersection {
		return method, nil
	}
	return "", errors.New("token endpoint authentication method resolution failed")
}

func validateJSONWebKeysURI(raw string) error {
	if len(raw) > maxOAuthURIBytes {
		return errors.New("jwks_uri is too long")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("parse jwks_uri: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("jwks_uri must use HTTPS and include a host")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("jwks_uri cannot contain user info or a fragment")
	}
	return nil
}

func rejectUnsafeRegistrationFields(raw map[string]json.RawMessage, allowClientID bool) error {
	for _, field := range []string{
		"client_secret",
		"client_secret_expires_at",
		"registration_access_token",
		"registration_client_uri",
		"metadata",
		"audience",
		"skip_consent",
		"skip_logout_consent",
		"access_token_strategy",
		"owner",
	} {
		if _, present := raw[field]; present {
			return fmt.Errorf("field %q is not allowed for dynamic MCP clients", field)
		}
	}
	if !allowClientID {
		if _, present := raw["client_id"]; present {
			return errors.New("client_id cannot be chosen during dynamic registration")
		}
	}
	return nil
}

func validateClientIDURL(raw string) (*url.URL, error) {
	if len(raw) > maxOAuthURIBytes {
		return nil, errors.New("client_id URL is too long")
	}
	if strings.Contains(raw, "#") {
		return nil, errors.New("client_id URL cannot contain a fragment")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("parse client_id URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("client_id URL must use HTTPS and include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("client_id URL cannot contain user info, a query, or a fragment")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return nil, errors.New("client_id URL must contain a non-root path")
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return nil, fmt.Errorf("decode client_id URL path: %w", err)
		}
		if decoded == "." || decoded == ".." {
			return nil, errors.New("client_id URL path cannot contain dot segments")
		}
	}
	return parsed, nil
}

func looksLikeURLClientID(clientID string) bool {
	parsed, err := url.Parse(clientID)
	return err == nil && parsed.IsAbs() &&
		(strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https"))
}

func validateRedirectURI(raw string) error {
	if len(raw) > maxOAuthURIBytes {
		return errors.New("redirect URI is too long")
	}
	if strings.Contains(raw, "#") {
		return errors.New("redirect URI cannot contain a fragment")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("parse URI: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("redirect URI must be absolute and include a host")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("redirect URI cannot contain user info or a fragment")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		hostname := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(hostname)
		if hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("redirect HTTP is allowed only for a loopback address")
		}
		if parsed.Port() == "" {
			return errors.New("redirect HTTP loopback URI must include an explicit port")
		}
		return nil
	default:
		return errors.New("redirect URI must use HTTPS or an HTTP loopback address")
	}
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range left {
		if slices.Contains(left[:index], value) || !slices.Contains(right, value) {
			return false
		}
	}
	return true
}
