package kratos_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	jsonnet "github.com/google/go-jsonnet"
)

func TestIdentitySchemaOwnsOnlyAccountEmailTraits(t *testing.T) {
	rawSchema, err := os.ReadFile("identity.schema.json")
	if err != nil {
		t.Fatalf("read identity schema: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		t.Fatalf("decode identity schema: %v", err)
	}
	traits := nestedMap(t, schema, "properties", "traits")
	properties := requiredMap(t, traits, "properties")
	keys := sortedKeys(properties)
	if !reflect.DeepEqual(keys, []string{"email", "pending_email"}) {
		t.Fatalf("identity trait keys = %#v, want canonical and pending email traits", keys)
	}
	if traits["additionalProperties"] != false {
		t.Fatalf("traits.additionalProperties = %#v, want false", traits["additionalProperties"])
	}
	required, ok := traits["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "email" {
		t.Fatalf("traits.required = %#v, want [email]", traits["required"])
	}
}

func TestOIDCMappersPersistCanonicalVerifiedAddressWithoutAuthorizationMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mapper string
		claims map[string]any
	}{
		{
			name:   "Google",
			mapper: "mappers/google.jsonnet",
			claims: map[string]any{
				"email":          "user@example.com",
				"email_verified": true,
				"name":           "Google User",
				"given_name":     "User",
				"family_name":    "Google",
				"picture":        "https://provider.example/google.jpg",
			},
		},
		{
			name:   "GitHub",
			mapper: "mappers/github.jsonnet",
			claims: map[string]any{
				"email":          "user@example.com",
				"email_verified": true,
				"name":           "GitHub User",
				"login":          "github-user",
				"username":       "github-user",
				"avatar_url":     "https://provider.example/github.png",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := evaluateMapper(t, tt.mapper, tt.claims)
			identity := requiredMap(t, output, "identity")
			traits := requiredMap(t, identity, "traits")
			if !reflect.DeepEqual(traits, map[string]any{"email": "user@example.com"}) {
				t.Fatalf("OIDC traits = %#v, want canonical email only", traits)
			}
			wantVerifiedAddresses := []any{map[string]any{"via": "email", "value": "user@example.com"}}
			if !reflect.DeepEqual(identity["verified_addresses"], wantVerifiedAddresses) {
				t.Fatalf("OIDC verified addresses = %#v, want provider-verified address", identity["verified_addresses"])
			}
			if _, present := identity["metadata_public"]; present {
				t.Fatalf("OIDC mapper wrote authorization metadata: %#v", identity["metadata_public"])
			}
		})
	}
}

func TestOIDCMappersDoNotProjectUnverifiedProviderEmail(t *testing.T) {
	for _, mapper := range []string{"mappers/google.jsonnet", "mappers/github.jsonnet"} {
		t.Run(mapper, func(t *testing.T) {
			output := evaluateMapper(t, mapper, map[string]any{
				"email":          "unverified@example.com",
				"email_verified": false,
			})
			identity := requiredMap(t, output, "identity")
			if traits := requiredMap(t, identity, "traits"); len(traits) != 0 {
				t.Fatalf("unverified OIDC traits = %#v, want empty", traits)
			}
			if addresses, ok := identity["verified_addresses"].([]any); !ok || len(addresses) != 0 {
				t.Fatalf("unverified OIDC addresses = %#v, want empty", identity["verified_addresses"])
			}
		})
	}
}

func TestRegistrationHooksProjectTransientPreferredLocale(t *testing.T) {
	ctx := map[string]any{
		"flow": map[string]any{
			"id":     "registration-flow-1",
			"type":   "browser",
			"active": "code",
			"transient_payload": map[string]any{
				"preferred_locale": "ko",
			},
		},
		"identity": map[string]any{
			"id": "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
			"traits": map[string]any{
				"email": "member@example.com",
			},
		},
	}

	afterRegistration := evaluateHook(t, "hooks/after-registration.jsonnet", ctx)
	wantAfter := map[string]any{
		"identity_id":      "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
		"email":            "member@example.com",
		"preferred_locale": "ko",
		"trigger":          "registration",
	}
	if !reflect.DeepEqual(afterRegistration, wantAfter) {
		t.Fatalf("after-registration projection = %#v, want %#v", afterRegistration, wantAfter)
	}

	policy := evaluateHook(t, "hooks/reject-credential-registration.jsonnet", ctx)
	wantPolicy := map[string]any{
		"flow_id":          "registration-flow-1",
		"flow_type":        "browser",
		"identity_id":      "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
		"email":            "member@example.com",
		"pending_email":    "",
		"method":           "code",
		"preferred_locale": "ko",
	}
	if !reflect.DeepEqual(policy, wantPolicy) {
		t.Fatalf("registration policy projection = %#v, want %#v", policy, wantPolicy)
	}

}

func TestLoginAndSettingsHooksProjectCanonicalIdentityState(t *testing.T) {
	ctx := map[string]any{
		"flow": map[string]any{"id": "flow-1", "type": "browser"},
		"identity": map[string]any{
			"id": "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
			"traits": map[string]any{
				"email":         "member@example.com",
				"pending_email": "next@example.com",
			},
		},
	}

	login := evaluateHook(t, "hooks/after-login.jsonnet", ctx)
	wantLogin := map[string]any{
		"identity_id": "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
		"email":       "member@example.com",
		"trigger":     "login",
	}
	if !reflect.DeepEqual(login, wantLogin) {
		t.Fatalf("after-login projection = %#v, want %#v", login, wantLogin)
	}

	settings := evaluateHook(t, "hooks/after-settings.jsonnet", ctx)
	wantSettings := map[string]any{
		"flow_id":       "flow-1",
		"identity_id":   "018f5e2a-7c31-7a43-8b7c-56e20c34a992",
		"email":         "member@example.com",
		"pending_email": "next@example.com",
		"flow_type":     "browser",
	}
	if !reflect.DeepEqual(settings, wantSettings) {
		t.Fatalf("after-settings projection = %#v, want %#v", settings, wantSettings)
	}
}

func evaluateMapper(t *testing.T, path string, claims map[string]any) map[string]any {
	t.Helper()
	vm := jsonnet.MakeVM()
	vm.Importer(&jsonnet.FileImporter{JPaths: []string{"."}})
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode claims: %v", err)
	}
	vm.ExtCode("claims", string(encoded))
	output, err := vm.EvaluateFile(path)
	if err != nil {
		t.Fatalf("evaluate %s: %v", path, err)
	}
	return decodeJSONOutput(t, path, output)
}

func evaluateHook(t *testing.T, path string, ctx map[string]any) map[string]any {
	t.Helper()
	vm := jsonnet.MakeVM()
	vm.Importer(&jsonnet.FileImporter{JPaths: []string{"."}})
	encoded, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("encode hook context: %v", err)
	}
	vm.ExtCode("ctx", string(encoded))
	snippet := fmt.Sprintf("(import %q)(std.extVar('ctx'))", path)
	output, err := vm.EvaluateAnonymousSnippet("member-identity-hook-test.jsonnet", snippet)
	if err != nil {
		t.Fatalf("evaluate %s: %v", path, err)
	}
	return decodeJSONOutput(t, path, output)
}

func decodeJSONOutput(t *testing.T, name, output string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("decode %s output: %v", name, err)
	}
	return decoded
}
