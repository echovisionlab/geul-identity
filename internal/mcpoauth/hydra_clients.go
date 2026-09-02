package mcpoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
)

const (
	hydraResponseLimit = 1 << 20
	cimdMarkerKind     = "mcp_cimd_v1"
)

type hydraClient struct {
	ID                          string          `json:"client_id"`
	Name                        string          `json:"client_name"`
	RedirectURIs                []string        `json:"redirect_uris"`
	GrantTypes                  []string        `json:"grant_types"`
	ResponseTypes               []string        `json:"response_types"`
	Scope                       string          `json:"scope"`
	Audience                    []string        `json:"audience"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	JSONWebKeysURI              string          `json:"jwks_uri,omitempty"`
	LogoURI                     string          `json:"logo_uri,omitempty"`
	ClientURI                   string          `json:"client_uri,omitempty"`
	PolicyURI                   string          `json:"policy_uri,omitempty"`
	TermsOfServiceURI           string          `json:"tos_uri,omitempty"`
	Contacts                    []string        `json:"contacts,omitempty"`
	SkipConsent                 bool            `json:"skip_consent"`
	Metadata                    json.RawMessage `json:"metadata"`
}

type hydraClientMarker struct {
	Kind     string `json:"kind"`
	ClientID string `json:"client_id"`
}

// HydraClientManager writes only validated URL-form CIMD clients through the
// private Hydra Admin API. It never creates opaque/static client IDs.
type HydraClientManager struct {
	adminBaseURL string
	client       *http.Client
	contract     Contract
	locks        [32]sync.Mutex
}

func NewHydraClientManager(adminBaseURL string, client *http.Client, contract Contract) (*HydraClientManager, error) {
	if err := contract.validate(); err != nil {
		return nil, fmt.Errorf("MCP OAuth contract: %w", err)
	}
	normalized, err := validateUpstreamBaseURL(adminBaseURL)
	if err != nil {
		return nil, fmt.Errorf("hydra admin URL: %w", err)
	}
	if client == nil {
		return nil, errors.New("hydra admin HTTP client is required")
	}
	adminClient := *client
	adminClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HydraClientManager{adminBaseURL: normalized, client: &adminClient, contract: contract}, nil
}

func (m *HydraClientManager) EnsureCIMDClient(ctx context.Context, metadata clientMetadata) error {
	var err error
	metadata, err = normalizeClientMetadata(metadata, true)
	if err != nil {
		return err
	}
	if _, err := validateClientIDURL(metadata.ClientID); err != nil {
		return err
	}
	marker, err := json.Marshal(hydraClientMarker{Kind: cimdMarkerKind, ClientID: metadata.ClientID})
	if err != nil {
		return fmt.Errorf("encode Hydra client marker: %w", err)
	}
	desired := hydraClient{
		ID:                          metadata.ClientID,
		Name:                        metadata.ClientName,
		RedirectURIs:                slices.Clone(metadata.RedirectURIs),
		GrantTypes:                  slices.Clone(metadata.GrantTypes),
		ResponseTypes:               []string{"code"},
		Scope:                       hydraClientScope,
		Audience:                    []string{m.contract.ResourceURL},
		TokenEndpointAuthMethod:     metadata.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg: metadata.TokenEndpointAuthAlg,
		JSONWebKeysURI:              metadata.JSONWebKeysURI,
		SkipConsent:                 false,
		Metadata:                    marker,
	}

	lock := &m.locks[clientLockIndex(metadata.ClientID)]
	lock.Lock()
	defer lock.Unlock()

	existing, found, err := m.get(ctx, metadata.ClientID)
	if err != nil {
		return err
	}
	if found {
		if !isManagedCIMDClient(existing) {
			return errors.New("url-form client_id conflicts with a client not managed by the CIMD facade")
		}
		if hydraClientsEqual(existing, desired) {
			return nil
		}
		return m.put(ctx, desired)
	}
	if err := m.create(ctx, desired); err == nil {
		return nil
	} else if !errors.Is(err, errHydraClientConflict) {
		return err
	}

	// Another facade replica may have created the same URL-form client after
	// the GET. Re-read and accept only the exact managed marker.
	existing, found, err = m.get(ctx, metadata.ClientID)
	if err != nil {
		return err
	}
	if !found || !isManagedCIMDClient(existing) {
		return errors.New("concurrent URL-form client registration conflicted with an unmanaged client")
	}
	if hydraClientsEqual(existing, desired) {
		return nil
	}
	return m.put(ctx, desired)
}

var errHydraClientConflict = errors.New("hydra client already exists")

func (m *HydraClientManager) get(ctx context.Context, clientID string) (hydraClient, bool, error) {
	endpoint := m.adminBaseURL + "/admin/clients/" + url.PathEscape(clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return hydraClient{}, false, fmt.Errorf("create Hydra client lookup: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	response, err := m.client.Do(req)
	if err != nil {
		return hydraClient{}, false, fmt.Errorf("lookup Hydra client: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return hydraClient{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return hydraClient{}, false, fmt.Errorf("lookup Hydra client returned HTTP %d", response.StatusCode)
	}
	var client hydraClient
	if err := decodeBoundedJSON(response.Body, &client); err != nil {
		return hydraClient{}, false, fmt.Errorf("decode Hydra client: %w", err)
	}
	if client.ID != clientID {
		return hydraClient{}, false, errors.New("hydra client lookup returned a mismatched client_id")
	}
	return client, true, nil
}

func (m *HydraClientManager) create(ctx context.Context, client hydraClient) error {
	status, err := m.send(ctx, http.MethodPost, m.adminBaseURL+"/admin/clients", client)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusCreated:
		return nil
	case http.StatusConflict:
		return errHydraClientConflict
	default:
		return fmt.Errorf("create Hydra client returned HTTP %d", status)
	}
}

func (m *HydraClientManager) put(ctx context.Context, client hydraClient) error {
	endpoint := m.adminBaseURL + "/admin/clients/" + url.PathEscape(client.ID)
	status, err := m.send(ctx, http.MethodPut, endpoint, client)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("update Hydra client returned HTTP %d", status)
	}
	return nil
}

func (m *HydraClientManager) send(ctx context.Context, method, endpoint string, client hydraClient) (int, error) {
	body, err := json.Marshal(client)
	if err != nil {
		return 0, fmt.Errorf("encode Hydra client: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create Hydra client request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := m.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("write Hydra client: %w", err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, hydraResponseLimit+1)); err != nil {
		return 0, fmt.Errorf("drain Hydra client response: %w", err)
	}
	return response.StatusCode, nil
}

func isManagedCIMDClient(client hydraClient) bool {
	var raw map[string]json.RawMessage
	if len(client.Metadata) == 0 || json.Unmarshal(client.Metadata, &raw) != nil || len(raw) != 2 {
		return false
	}
	if _, ok := raw["kind"]; !ok {
		return false
	}
	if _, ok := raw["client_id"]; !ok {
		return false
	}
	var marker hydraClientMarker
	if json.Unmarshal(client.Metadata, &marker) != nil {
		return false
	}
	return marker.Kind == cimdMarkerKind && marker.ClientID == client.ID && looksLikeURLClientID(client.ID)
}

func hydraClientsEqual(left, right hydraClient) bool {
	return left.ID == right.ID &&
		left.Name == right.Name &&
		slices.Equal(left.RedirectURIs, right.RedirectURIs) &&
		slices.Equal(left.GrantTypes, right.GrantTypes) &&
		slices.Equal(left.ResponseTypes, right.ResponseTypes) &&
		left.Scope == right.Scope &&
		slices.Equal(left.Audience, right.Audience) &&
		left.TokenEndpointAuthMethod == right.TokenEndpointAuthMethod &&
		left.TokenEndpointAuthSigningAlg == right.TokenEndpointAuthSigningAlg &&
		left.JSONWebKeysURI == right.JSONWebKeysURI &&
		left.LogoURI == "" && left.ClientURI == "" && left.PolicyURI == "" &&
		left.TermsOfServiceURI == "" && len(left.Contacts) == 0 &&
		!left.SkipConsent && isManagedCIMDClient(left)
}

func clientLockIndex(clientID string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(clientID))
	return hash.Sum32() % 32
}

func validateUpstreamBaseURL(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("upstream URL must be an absolute HTTP(S) origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("upstream URL must not include credentials, a path, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func decodeBoundedJSON(reader io.Reader, target any) error {
	limited := &io.LimitedReader{R: reader, N: hydraResponseLimit + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if limited.N <= 0 {
		return errors.New("response JSON exceeds the size limit")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return nil
}
