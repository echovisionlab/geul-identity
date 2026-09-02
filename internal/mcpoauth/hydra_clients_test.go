package mcpoauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHydraClientManagerEscapesURLIDAndCreatesOnlyManagedCIMDClient(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/oauth/client.json"
	mux := http.NewServeMux()
	var created hydraClient
	mux.HandleFunc("GET /admin/clients/{client_id}", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("client_id") != clientID {
			t.Fatalf("Hydra client path value = %q", request.PathValue("client_id"))
		}
		writer.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /admin/clients", func(writer http.ResponseWriter, request *http.Request) {
		decodeJSONBody(t, request.Body, &created)
		writer.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	manager, err := NewHydraClientManager(server.URL, server.Client(), testContract)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureCIMDClient(t.Context(), clientMetadata{
		ClientID:                clientID,
		ClientName:              "CIMD Client",
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "private_key_jwt",
		TokenEndpointAuthAlg:    "RS256",
		JSONWebKeysURI:          "https://client.example/oauth/jwks.json",
		Scope:                   Scope,
	}); err != nil {
		t.Fatal(err)
	}
	if created.ID != clientID || !isManagedCIMDClient(created) || created.SkipConsent ||
		created.TokenEndpointAuthMethod != "private_key_jwt" || created.TokenEndpointAuthSigningAlg != "RS256" ||
		created.JSONWebKeysURI != "https://client.example/oauth/jwks.json" ||
		!sameStringSet(created.GrantTypes, []string{"authorization_code", "refresh_token"}) || created.Scope != hydraClientScope {
		t.Fatalf("created Hydra client = %#v", created)
	}
}

func TestHydraClientManagerUpdatesOnlyExistingManagedCIMDClient(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example/oauth/client.json"
	marker, _ := json.Marshal(hydraClientMarker{Kind: cimdMarkerKind, ClientID: clientID})
	existing := hydraClient{
		ID:                      clientID,
		Name:                    "Old Name",
		RedirectURIs:            []string{"https://client.example/old"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scope:                   hydraClientScope,
		Audience:                []string{testContract.ResourceURL},
		TokenEndpointAuthMethod: "none",
		Metadata:                marker,
	}
	var updated hydraClient
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/clients/{client_id}", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("client_id") != clientID {
			t.Fatalf("Hydra client path value = %q", request.PathValue("client_id"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(existing)
	})
	mux.HandleFunc("PUT /admin/clients/{client_id}", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("client_id") != clientID {
			t.Fatalf("Hydra client path value = %q", request.PathValue("client_id"))
		}
		decodeJSONBody(t, request.Body, &updated)
		writer.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	manager, err := NewHydraClientManager(server.URL, server.Client(), testContract)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureCIMDClient(t.Context(), clientMetadata{
		ClientID:                clientID,
		ClientName:              "New Name",
		RedirectURIs:            []string{"https://client.example/new"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   Scope,
	}); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "New Name" || updated.RedirectURIs[0] != "https://client.example/new" ||
		len(updated.GrantTypes) != 1 || !isManagedCIMDClient(updated) || updated.SkipConsent {
		t.Fatalf("updated Hydra client = %#v", updated)
	}
}
