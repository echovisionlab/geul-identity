package oathkeeperrules

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestMCPRuleUsesOnlyHydraOAuthAndOneAssertionShape(t *testing.T) {
	rules, err := generateRules(repositoryRouteConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	block := ruleBlock(t, rules, "mcp")
	for _, want := range []string{
		`url: '<https://site\.example\.invalid/mcp>'`,
		"      - GET\n",
		"      - POST\n",
		"    - handler: oauth2_introspection\n",
		"    - handler: www_authenticate\n",
		"        resource_metadata: 'https://site.example.invalid/.well-known/oauth-protected-resource/mcp'\n",
		"        scope: 'mcp'\n",
		"    handler: remote_json\n",
		"      remote: 'http://authorization.example.invalid:8001/internal/mcp/admission/is-author'\n",
		`          "account_identity_id": "`,
		"          Authorization: ''\n",
		"          Cookie: ''\n",
		"          X-Session-Id: ''\n",
		"          '__AUTH_HEADER_NAME__': '",
		`          '__INTERNAL_SERVICE_HEADER_NAME__': '{{ env "TOKEN_SIGNING_SECRET" }}'`,
		"    url: 'http://api.example.invalid:8000'\n",
	} {
		if !bytes.Contains(block, []byte(want)) {
			t.Errorf("MCP rule is missing %q:\n%s", want, block)
		}
	}
	for _, forbidden := range []string{
		"handler: bearer_token", "handler: cookie_session", "mcp_pat", "/internal/mcp/pat/whoami",
		`"session_id":`, `"member_id":`, `"role":`, `"permission":`, "strip_path:", "/api/rpc",
	} {
		if bytes.Contains(block, []byte(forbidden)) {
			t.Errorf("MCP rule contains forbidden boundary %q:\n%s", forbidden, block)
		}
	}

	root := mustRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "config/oathkeeper/oathkeeper.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	authenticators := config["authenticators"].(map[string]any)
	if _, exists := authenticators["bearer_token"]; exists {
		t.Fatal("Remote MCP PAT verifier remains configured")
	}
	oauth := authenticators["oauth2_introspection"].(map[string]any)
	if got := oauth["enabled"]; got != true {
		t.Fatalf("oauth2_introspection enabled = %#v", got)
	}
	oauthConfig := oauth["config"].(map[string]any)
	for key, want := range map[string]any{
		"introspection_url": "__HYDRA_ADMIN_URL__/admin/oauth2/introspect",
		"scope_strategy":    "exact",
	} {
		if got := oauthConfig[key]; got != want {
			t.Errorf("oauth2_introspection %s = %#v, want %#v", key, got, want)
		}
	}
	for key, want := range map[string]string{
		"required_scope": "mcp", "target_audience": "https://site.example.invalid/mcp", "trusted_issuers": "https://sso.example.invalid",
	} {
		values, ok := oauthConfig[key].([]any)
		if !ok || len(values) != 1 || values[0] != want {
			t.Errorf("oauth2_introspection %s = %#v, want [%q]", key, oauthConfig[key], want)
		}
	}
}

func TestMCPPreflightUsesTheExactResourceWithoutOAuth(t *testing.T) {
	routes := repositoryRouteConfig(t)
	rules, err := generateRules(routes)
	if err != nil {
		t.Fatal(err)
	}
	preflight := ruleBlock(t, rules, "mcp-preflight")
	for _, want := range []string{
		"url: '<" + exactOriginPattern(routes.Origins.API) + "/mcp>'",
		"      - OPTIONS\n",
		"    - handler: anonymous\n",
		"    handler: allow\n",
		"    - handler: header\n",
		"    url: '" + routes.Upstreams.API + "'\n",
	} {
		if !bytes.Contains(preflight, []byte(want)) {
			t.Errorf("MCP preflight rule is missing %q:\n%s", want, preflight)
		}
	}
	for _, forbidden := range []string{
		"handler: oauth2_introspection", "handler: remote_json", "handler: www_authenticate",
		"__AUTH_HEADER_NAME__", "__INTERNAL_SERVICE_HEADER_NAME__", "GET", "POST",
	} {
		if bytes.Contains(preflight, []byte(forbidden)) {
			t.Errorf("MCP preflight contains forbidden boundary %q:\n%s", forbidden, preflight)
		}
	}

	mcp := ruleBlock(t, rules, "mcp")
	if bytes.Contains(mcp, []byte("      - OPTIONS\n")) {
		t.Errorf("OAuth MCP rule also admits OPTIONS:\n%s", mcp)
	}
}

func TestMCPAssertionTemplatesAcceptOnlyOAuthAttribution(t *testing.T) {
	identityID := "018f5e2a-7c31-7a43-8b7c-56e20c34a994"
	context := base64.RawURLEncoding.EncodeToString([]byte("typed-protobuf-context"))
	principal := func(subject, authenticatedContext string) gatewayTemplateSession {
		return gatewayTemplateSession{Subject: subject, Extra: map[string]any{
			"authenticated_context_b64": authenticatedContext,
		}}
	}
	valid := principal(identityID, context)
	for name, assertion := range map[string]struct {
		template string
		want     string
	}{
		"identity": {mcpIdentityIDTemplate, identityID},
		"context":  {mcpAuthenticatedContextTemplate, context},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := executeGatewayTemplate(t, assertion.template, valid)
			if err != nil || got != assertion.want {
				t.Fatalf("assertion = %q, error = %v; want %q", got, err, assertion.want)
			}
		})
	}

	for _, test := range []struct {
		name      string
		template  string
		principal gatewayTemplateSession
	}{
		{"missing identity", mcpIdentityIDTemplate, principal("", context)},
		{"malformed identity", mcpIdentityIDTemplate, principal("not-a-uuid", context)},
		{"missing context", mcpAuthenticatedContextTemplate, principal(identityID, "")},
		{"malformed context", mcpAuthenticatedContextTemplate, principal(identityID, "***")},
		{"padded context", mcpAuthenticatedContextTemplate, principal(identityID, "dGVzdA==")},
		{"oversized context", mcpAuthenticatedContextTemplate, principal(identityID, strings.Repeat("A", 3504))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if value, err := executeGatewayTemplate(t, test.template, test.principal); err == nil {
				t.Fatalf("invalid OAuth introspection result produced assertion %q", value)
			}
		})
	}
}
