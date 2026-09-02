package oathkeeperrules

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	_ "github.com/echovisionlab/geul-event-contracts/gen/api/manage/v1"
	policyv1 "github.com/echovisionlab/geul-event-contracts/gen/api/policy/v1"
	"github.com/echovisionlab/geul-identity/internal/authboundary"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	"sigs.k8s.io/yaml"
)

type serviceMethods map[string][]string

const (
	oathkeeperRuleVersion           = "v26.2.0"
	rulesFile                       = "config/oathkeeper/rules.yml"
	routesFile                      = "config/oathkeeper/routes.yml"
	memberUUIDPattern               = `^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	canonicalBase64URLPattern       = `^([A-Za-z0-9_-]{4})*([A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$`
	mcpContextMinEncodedChars       = `2`
	mcpContextMaxEncodedChars       = `3500`
	mcpAuthorAdmissionURL           = "http://authorization.example.invalid:8001/internal/mcp/admission/is-author"
	memberSubjectTemplate           = `{{- $accountIdentityID := print .Subject -}}{{- if not (regexMatch "` + memberUUIDPattern + `" $accountIdentityID) -}}{{- fail "missing or malformed account identity subject" -}}{{- end -}}{{- $accountIdentityID -}}`
	gatewaySessionIDTemplate        = `{{- $sessionID := "" -}}{{- if .Extra -}}{{- $sessionID = print .Extra.id -}}{{- end -}}{{- if not (regexMatch "` + memberUUIDPattern + `" $sessionID) -}}{{- fail "missing or malformed Kratos session id" -}}{{- end -}}{{- $sessionID -}}`
	mcpIdentityIDTemplate           = `{{- $identityID := print .Subject -}}{{- if not (regexMatch "` + memberUUIDPattern + `" $identityID) -}}{{- fail "missing or malformed MCP identity id" -}}{{- end -}}{{- $identityID -}}`
	mcpAuthenticatedContextTemplate = `{{- $context := "" -}}{{- if .Extra -}}{{- $context = print .Extra.authenticated_context_b64 -}}{{- end -}}{{- if or (lt (len $context) ` + mcpContextMinEncodedChars + `) (gt (len $context) ` + mcpContextMaxEncodedChars + `) (not (regexMatch "` + canonicalBase64URLPattern + `" $context)) -}}{{- fail "missing or malformed MCP authenticated context" -}}{{- end -}}{{- $context -}}`
)

type routeConfig struct {
	Origins struct {
		API         string `yaml:"api"`
		APIInternal string `json:"api_internal" yaml:"api_internal"`
		Auth        string `yaml:"auth"`
		Collab      string `yaml:"collab"`
	} `yaml:"origins"`
	Upstreams struct {
		API    string `yaml:"api"`
		Collab string `yaml:"collab"`
	} `yaml:"upstreams"`
}

func Sync(root string, check bool) error {
	routes, err := loadRouteConfig(root)
	if err != nil {
		return err
	}
	return syncWithGenerator(root, check, func() ([]byte, error) {
		return generateRules(routes)
	})
}

func loadRouteConfig(root string) (routeConfig, error) {
	var routes routeConfig
	raw, err := os.ReadFile(filepath.Join(root, routesFile))
	if err != nil {
		return routes, fmt.Errorf("read %s: %w", routesFile, err)
	}
	if err := yaml.UnmarshalStrict(raw, &routes); err != nil {
		return routes, fmt.Errorf("parse %s: %w", routesFile, err)
	}
	if err := routes.validate(); err != nil {
		return routeConfig{}, fmt.Errorf("validate %s: %w", routesFile, err)
	}
	return routes, nil
}

func (c routeConfig) validate() error {
	origins := []struct {
		name  string
		value string
	}{
		{name: "origins.api", value: c.Origins.API},
		{name: "origins.auth", value: c.Origins.Auth},
		{name: "origins.collab", value: c.Origins.Collab},
	}
	for _, candidate := range origins {
		_, err := validateAbsoluteURL(candidate.name, candidate.value, true)
		if err != nil {
			return err
		}
	}
	if _, err := validateAbsoluteURL("origins.api_internal", c.Origins.APIInternal, false); err != nil {
		return err
	}

	for _, candidate := range []struct {
		name  string
		value string
	}{
		{name: "upstreams.api", value: c.Upstreams.API},
		{name: "upstreams.collab", value: c.Upstreams.Collab},
	} {
		if _, err := validateAbsoluteURL(candidate.name, candidate.value, false); err != nil {
			return err
		}
	}
	return nil
}

func validateAbsoluteURL(name, value string, publicOrigin bool) (string, error) {
	trimmed := strings.TrimSpace(value)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%s must be an absolute HTTP(S) URL: %w", name, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("%s must be an absolute HTTP(S) URL with no userinfo", name)
	}
	if publicOrigin && parsed.Scheme != "https" {
		return "", fmt.Errorf("%s must use HTTPS", name)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must be an origin with no path, query, or fragment", name)
	}
	return parsed.String(), nil
}

func exactOriginPattern(origin string) string {
	return regexp.QuoteMeta(strings.TrimSpace(origin))
}

func publicPathPattern(origin, prefix string) string {
	return exactOriginPattern(origin) + regexp.QuoteMeta(prefix)
}

func apiRPCPathPattern(routes routeConfig) string {
	publicPattern := publicPathPattern(routes.Origins.API, "/api/rpc")
	internalPattern := publicPathPattern(routes.Origins.APIInternal, "/api/rpc")
	return "(?:" + publicPattern + "|" + internalPattern + ")"
}

func syncWithGenerator(root string, check bool, generate func() ([]byte, error)) error {
	rules, err := generate()
	if err != nil {
		return fmt.Errorf("generate rules: %w", err)
	}
	rulesPath := filepath.Join(root, rulesFile)

	if check {
		current, err := os.ReadFile(rulesPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", rulesFile, err)
		}
		if !bytes.Equal(current, rules) {
			return fmt.Errorf("%s is stale; run `npm run generate:oathkeeper-rules`", rulesFile)
		}
		return nil
	}

	if err := os.WriteFile(rulesPath, rules, 0644); err != nil {
		return fmt.Errorf("write %s: %w", rulesFile, err)
	}
	return nil
}

func generateRules(routes routeConfig) ([]byte, error) {
	return generateRulesWithCollector(routes, collectManageAuthorizationRoles)
}

func generateRulesWithCollector(routes routeConfig, collect func() (map[policyv1.AuthorizationRole]serviceMethods, error)) ([]byte, error) {
	if err := routes.validate(); err != nil {
		return nil, fmt.Errorf("validate routes: %w", err)
	}
	roles, err := collect()
	if err != nil {
		return nil, fmt.Errorf("collect manage access roles: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(generatedHeader())
	out.WriteString(staticBaseRules(routes))

	// Keep deterministic order in output for stable diffs.
	roleOrder := []policyv1.AuthorizationRole{
		policyv1.AuthorizationRole_ADMIN,
		policyv1.AuthorizationRole_AUTHOR,
		policyv1.AuthorizationRole_USER,
	}
	for _, role := range roleOrder {
		services := roles[role]
		if len(services) == 0 {
			continue
		}
		// Oathkeeper evaluates every rule when matching a request. Methods that
		// share a role also share the complete authentication, authorization,
		// mutation, and upstream policy, so emit one exact allowlist per role.
		// The matcher still enumerates every service/method pair; it must never
		// be widened to an api.manage.v1 wildcard.
		writeRoleRule(&out, routes, role, services)
	}

	out.WriteString(staticTailRules(routes))
	return out.Bytes(), nil
}

func collectManageAuthorizationRoles() (map[policyv1.AuthorizationRole]serviceMethods, error) {
	return collectManageAuthorizationRolesFrom(protoregistry.GlobalFiles)
}

type fileRanger interface {
	RangeFiles(func(protoreflect.FileDescriptor) bool)
}

func collectManageAuthorizationRolesFrom(files fileRanger) (map[policyv1.AuthorizationRole]serviceMethods, error) {
	result := map[policyv1.AuthorizationRole]serviceMethods{}

	var collectionErr error
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != "api.manage.v1" {
			return true
		}

		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			serviceName := string(svc.Name())

			for j := 0; j < svc.Methods().Len(); j++ {
				method := svc.Methods().Get(j)
				methodName := string(method.Name())

				opts := method.Options().(*descriptorpb.MethodOptions)
				if !proto.HasExtension(opts, policyv1.E_Access) {
					collectionErr = fmt.Errorf("missing access option for %s.%s", serviceName, methodName)
					return false
				}
				access := proto.GetExtension(opts, policyv1.E_Access).(*policyv1.AccessPolicy)
				if access.Role == policyv1.AuthorizationRole_UNSPECIFIED {
					collectionErr = fmt.Errorf("unspecified access role for %s.%s", serviceName, methodName)
					return false
				}
				switch access.Role {
				case policyv1.AuthorizationRole_USER,
					policyv1.AuthorizationRole_AUTHOR,
					policyv1.AuthorizationRole_ADMIN:
				case policyv1.AuthorizationRole_ANON:
					collectionErr = fmt.Errorf("public access role is not allowed for manage RPC %s.%s", serviceName, methodName)
					return false
				default:
					collectionErr = fmt.Errorf("unsupported access role %d for %s.%s", access.Role, serviceName, methodName)
					return false
				}

				if _, ok := result[access.Role]; !ok {
					result[access.Role] = serviceMethods{}
				}
				result[access.Role][serviceName] = append(result[access.Role][serviceName], methodName)
			}
		}
		return true
	})
	if collectionErr != nil {
		return nil, collectionErr
	}

	for role, services := range result {
		for service, methods := range services {
			sort.Strings(methods)
			result[role][service] = methods
		}
	}
	return result, nil
}

func writeRoleRule(out *bytes.Buffer, routes routeConfig, role policyv1.AuthorizationRole, services serviceMethods) {
	serviceNames := make([]string, 0, len(services))
	for service := range services {
		serviceNames = append(serviceNames, service)
	}
	sort.Strings(serviceNames)

	out.WriteString("\n# =============================================================================\n")
	out.WriteString(fmt.Sprintf("# Manage API - %s role (generated from proto access options)\n", strings.ToLower(role.String())))
	out.WriteString("# =============================================================================\n\n")

	urlPattern := fmt.Sprintf(
		"<%s/api\\.manage\\.v1\\.%s>",
		apiRPCPathPattern(routes),
		serviceMethodRegexGroup(serviceNames, services),
	)
	out.WriteString(fmt.Sprintf("- id: manage-%s\n", roleID(role)))
	out.WriteString(fmt.Sprintf("  version: %s\n", oathkeeperRuleVersion))
	out.WriteString("  match:\n")
	out.WriteString(fmt.Sprintf("    url: '%s'\n", urlPattern))
	out.WriteString("    methods:\n")
	out.WriteString("      - POST\n")
	out.WriteString("  authenticators:\n")
	out.WriteString("    - handler: cookie_session\n")
	writeRoleAuthorizer(out, role)
	out.WriteString("  mutators:\n")
	out.WriteString("    - handler: header\n")
	out.WriteString("  upstream:\n")
	out.WriteString(fmt.Sprintf("    url: '%s'\n", routes.Upstreams.API))
	out.WriteString("    strip_path: /api/rpc\n")
}

func writeRoleAuthorizer(out *bytes.Buffer, role policyv1.AuthorizationRole) {
	if role == policyv1.AuthorizationRole_USER {
		out.WriteString("  authorizer:\n")
		out.WriteString("    handler: allow\n")
		return
	}
	if role != policyv1.AuthorizationRole_AUTHOR && role != policyv1.AuthorizationRole_ADMIN {
		panic(fmt.Sprintf("unsupported access role: %s", role.String()))
	}

	out.WriteString("  authorizer:\n")
	out.WriteString("    handler: remote_json\n")
	out.WriteString("    config:\n")
	out.WriteString("      payload: |\n")
	out.WriteString("        {\n")
	out.WriteString("          \"account_identity_id\": \"")
	out.WriteString(memberSubjectTemplate)
	out.WriteString("\",\n")
	out.WriteString("          \"session_id\": \"")
	out.WriteString(gatewaySessionIDTemplate)
	out.WriteString("\",\n")
	out.WriteString(fmt.Sprintf("          \"role\": \"%s\"\n", role.String()))
	out.WriteString("        }\n")
}

func methodRegexGroup(methods []string) string {
	if len(methods) == 1 {
		return regexp.QuoteMeta(methods[0])
	}
	escaped := make([]string, 0, len(methods))
	for _, method := range methods {
		escaped = append(escaped, regexp.QuoteMeta(method))
	}
	return "(?:" + strings.Join(escaped, "|") + ")"
}

// serviceMethodRegexGroup returns an exact fully-qualified Connect procedure
// allowlist. Each alternative keeps its service and methods together so a
// method with the same name in another service cannot inherit its role.
func serviceMethodRegexGroup(serviceNames []string, services serviceMethods) string {
	patterns := make([]string, 0, len(serviceNames))
	for _, service := range serviceNames {
		patterns = append(patterns, regexp.QuoteMeta(service)+"/"+methodRegexGroup(services[service]))
	}
	if len(patterns) == 1 {
		return patterns[0]
	}
	return "(?:" + strings.Join(patterns, "|") + ")"
}

func roleID(t policyv1.AuthorizationRole) string {
	switch t {
	case policyv1.AuthorizationRole_USER:
		return "auth"
	case policyv1.AuthorizationRole_AUTHOR:
		return "author"
	case policyv1.AuthorizationRole_ADMIN:
		return "admin"
	default:
		return "unknown"
	}
}

func generatedHeader() string {
	return `# Code generated by cmd/generate-oathkeeper-rules. DO NOT EDIT.
# Source of truth: github.com/echovisionlab/geul-event-contracts proto/api/manage/v1/* method options (api.policy.v1.access).
# Route origins and upstreams: config/oathkeeper/routes.yml.
# Manage rules group only identical gateway roles and still enumerate every exact Service/Method path.
# The typed MCP header keys remain placeholders until the deployment renderer
# validates and applies AUTH_HEADER_NAME and INTERNAL_SERVICE_HEADER_NAME.

`
}

func staticBaseRules(routes routeConfig) string {
	apiOrigin := exactOriginPattern(routes.Origins.API)
	apiRPCOrigin := apiRPCPathPattern(routes)
	apiPublicRPCOrigin := publicPathPattern(routes.Origins.API, "/api/rpc")
	apiUploadOrigin := publicPathPattern(routes.Origins.API, "/api")
	authOrigin := publicPathPattern(routes.Origins.Auth, "/api/auth")
	collabOrigin := publicPathPattern(routes.Origins.Collab, "/collab")
	return fmt.Sprintf(`# =============================================================================
# API health - exact API origin only
# =============================================================================

- id: api-health
  version: %[1]s
  match:
    url: '<%[2]s/health>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[6]s'

# =============================================================================
# SES provider callback - exact API origin/path only
# The API authenticates AWS SNS signature and the configured TopicArn.
# =============================================================================

- id: api-ses-callback
  version: %[1]s
  match:
    url: '<%[2]s/callbacks/ses>'
    methods:
      - POST
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[6]s'

# =============================================================================
# Collab WebSocket - exact collaboration origin only
# Document authorization is enforced by the Collab server.
# =============================================================================

- id: collab-websocket
  version: %[1]s
  match:
    url: '<%[5]s/(?P<type>post|work|release|label|artist|form)/(?P<id>[^/]+)/(?P<locale>[^/]+)>'
    methods:
      - GET
  authenticators:
    - handler: cookie_session
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[7]s'
    strip_path: /collab
    preserve_host: true

# =============================================================================
# Collab WebSocket (Admin-only docs) - exact collaboration origin only
# =============================================================================

- id: collab-websocket-admin
  version: %[1]s
  match:
    url: '<%[5]s/(?P<type>page|menu|campaign|email-template|email-layout|terms-history|privacy-history|map-theme|program-event)/(?P<id>[^/]+)/(?P<locale>[^/]+)>'
    methods:
      - GET
  authenticators:
    - handler: cookie_session
  authorizer:
    handler: remote_json
    config:
      payload: |
        {
          "account_identity_id": "%[8]s",
          "session_id": "%[9]s",
          "role": "ADMIN"
        }
  mutators:
    - handler: header
  upstream:
    url: '%[7]s'
    strip_path: /collab
    preserve_host: true

# =============================================================================
# API CORS preflight - exact API origin only
# =============================================================================

- id: api-rpc-preflight
  version: %[1]s
  match:
    url: '<%[11]s/api\.(?:open|manage)\.v1\..*>'
    methods:
      - OPTIONS
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[6]s'
    strip_path: /api/rpc

- id: upload-preflight
  version: %[1]s
  match:
    url: '<%[10]s/upload/.*>'
    methods:
      - OPTIONS
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[6]s'
    strip_path: /api

# =============================================================================
# Internal API - explicit public deny on the exact API origin
# =============================================================================

- id: block-internal-api
  version: %[1]s
  match:
    url: '<%[3]s/api\.intra\.v1\..*>'
    methods:
      - GET
      - HEAD
      - POST
      - PUT
      - PATCH
      - DELETE
      - OPTIONS
  authenticators:
    - handler: unauthorized
  authorizer:
    handler: deny
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/rpc

# =============================================================================
# Authentication origin - anonymous exact-path router to the API auth proxy
# Kratos owns flow/CSRF/session behavior behind the API proxy.
# =============================================================================

- id: auth-preflight
  version: %[1]s
  match:
    url: '<%[4]s(?:/login(?:/flows)?|/self-service/(?:(?:verification|settings)(?:/(?:browser|flows))?|logout(?:/browser)?|errors|methods/oidc/callback/[^/]+)|/sessions/.*|/schemas/.*|/health/.*|/\.well-known/ory/webauthn\.js)>'
    methods:
      - OPTIONS
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-login
  version: %[1]s
  match:
    url: '<%[4]s/login>'
    methods:
      - GET
      - POST
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-login-flows
  version: %[1]s
  match:
    url: '<%[4]s/login/flows>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-self-service-read
  version: %[1]s
  match:
    url: '<%[4]s/self-service/(?:(?:verification|settings)/(?:browser|flows)|logout(?:/browser)?|errors|methods/oidc/callback/[^/]+)>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-self-service-submit
  version: %[1]s
  match:
    url: '<%[4]s/self-service/(?:verification|settings)>'
    methods:
      - POST
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-sessions
  version: %[1]s
  match:
    url: '<%[4]s/sessions/.*>'
    methods:
      - GET
      - DELETE
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-schemas
  version: %[1]s
  match:
    url: '<%[4]s/schemas/.*>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-health
  version: %[1]s
  match:
    url: '<%[4]s/health/.*>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth

- id: auth-webauthn-runtime
  version: %[1]s
  match:
    url: '<%[4]s/\.well-known/ory/webauthn\.js>'
    methods:
      - GET
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: noop
  upstream:
    url: '%[6]s'
    strip_path: /api/auth
`, oathkeeperRuleVersion, apiOrigin, apiRPCOrigin, authOrigin, collabOrigin, routes.Upstreams.API, routes.Upstreams.Collab, memberSubjectTemplate, gatewaySessionIDTemplate, apiUploadOrigin, apiPublicRPCOrigin)
}

func staticTailRules(routes routeConfig) string {
	apiOrigin := exactOriginPattern(routes.Origins.API)
	apiRPCOrigin := apiRPCPathPattern(routes)
	apiUploadOrigin := publicPathPattern(routes.Origins.API, "/api")
	return fmt.Sprintf(`
# =============================================================================
# Remote MCP - exact API origin/path and Hydra OAuth only
# Hydra introspection projects one validated Identity/Member/delegation
# assertion. Personal access tokens have no MCP authenticator or fallback path.
# =============================================================================

- id: mcp-preflight
  version: %[1]s
  match:
    url: '<%[2]s/mcp>'
    methods:
      - OPTIONS
  authenticators:
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[5]s'

- id: mcp
  version: %[1]s
  match:
    url: '<%[2]s/mcp>'
    methods:
      - GET
      - POST
  authenticators:
    - handler: oauth2_introspection
  errors:
    - handler: www_authenticate
      config:
        resource_metadata: '%[9]s/.well-known/oauth-protected-resource/mcp'
        scope: 'mcp'
  authorizer:
    handler: remote_json
    config:
      remote: '%[8]s'
      payload: |
        {
          "account_identity_id": "%[6]s"
        }
  mutators:
    - handler: header
      config:
        headers:
          Authorization: ''
          Cookie: ''
          X-Session-Id: ''
          '%[10]s': '%[7]s'
          '%[11]s': '{{ env "TOKEN_SIGNING_SECRET" }}'
  upstream:
    url: '%[5]s'

# =============================================================================
# Open API - Authentication optional (anonymous fallback), exact API origin only
# =============================================================================

- id: open-api
  version: %[1]s
  match:
    url: '<%[3]s/api\.open\.v1\..*>'
    methods:
      - POST
  authenticators:
    - handler: cookie_session
    - handler: anonymous
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[5]s'
    strip_path: /api/rpc

# =============================================================================
# Upload endpoint - requires authentication, exact API origin only
# =============================================================================

- id: upload-endpoint
  version: %[1]s
  match:
    url: '<%[4]s/upload/.*>'
    methods:
      - POST
      - PUT
  authenticators:
    - handler: cookie_session
  authorizer:
    handler: allow
  mutators:
    - handler: header
  upstream:
    url: '%[5]s'
    strip_path: /api
`, oathkeeperRuleVersion, apiOrigin, apiRPCOrigin, apiUploadOrigin, routes.Upstreams.API, mcpIdentityIDTemplate, mcpAuthenticatedContextTemplate, mcpAuthorAdmissionURL, routes.Origins.API, authboundary.AuthHeaderNamePlaceholder, authboundary.InternalServiceHeaderNamePlaceholder)
}

func FindRepoRoot(start string) (string, error) {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repository root not found from %s", start)
		}
		dir = parent
	}
}
