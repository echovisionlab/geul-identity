package kratos_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	jsonnet "github.com/google/go-jsonnet"
	"sigs.k8s.io/yaml"
)

func TestPasswordlessAndPasskeyConfigurationContract(t *testing.T) {
	config := readYAMLMap(t, "kratos.yml")

	security := nestedMap(t, config, "security", "account_enumeration")
	if security["mitigate"] != true {
		t.Fatalf("security.account_enumeration.mitigate = %#v, want true", security["mitigate"])
	}

	methods := nestedMap(t, config, "selfservice", "methods")
	password := requiredMap(t, methods, "password")
	if password["enabled"] != false {
		t.Fatalf("password.enabled = %#v, want false for every account role", password["enabled"])
	}
	code := requiredMap(t, methods, "code")
	if code["enabled"] != true || code["passwordless_enabled"] != true || code["mfa_enabled"] != false {
		t.Fatalf("code method = %#v", code)
	}
	codeConfig := requiredMap(t, code, "config")
	if codeConfig["max_submissions"] != float64(5) || codeConfig["missing_credential_fallback_enabled"] != false {
		t.Fatalf("code config = %#v, want five attempts and no legacy credential fallback", codeConfig)
	}
	passkey := requiredMap(t, methods, "passkey")
	if passkey["enabled"] != true {
		t.Fatalf("passkey.enabled = %#v, want true", passkey["enabled"])
	}
	rp := nestedMap(t, passkey, "config", "rp")
	if rp["display_name"] != "Geul" || rp["id"] != "${KRATOS_PASSKEY_RP_ID}" {
		t.Fatalf("passkey RP = %#v", rp)
	}
	assertStringSlice(t, rp["origins"], "${SITE_ORIGIN}")
	link := requiredMap(t, methods, "link")
	if link["enabled"] != false {
		t.Fatalf("link.enabled = %#v, want false without password recovery", link["enabled"])
	}
	courierHeaders := nestedMap(t, config, "courier", "http", "request_config", "headers")
	if courierHeaders["Content-Type"] != "application/json" {
		t.Fatalf("courier headers = %#v, want JSON content type", courierHeaders)
	}
	assertInternalServiceAPIKey(t, nestedMap(t, config, "courier", "http", "request_config"))

	providers := requiredSlice(t, requiredMap(t, methods, "oidc"), "config", "providers")
	if len(providers) != 2 {
		t.Fatalf("OIDC providers = %#v, want Google and GitHub", providers)
	}
	for _, rawProvider := range providers {
		provider := requiredObject(t, rawProvider)
		if provider["account_linking_mode"] != "confirm_with_existing_credential" {
			t.Fatalf("OIDC provider %q account_linking_mode = %#v", provider["id"], provider["account_linking_mode"])
		}
		switch provider["id"] {
		case "google":
			assertStringSlice(t, provider["scope"], "email", "profile", "openid")
		case "github":
			assertStringSlice(t, provider["scope"], "read:user", "user:email")
		default:
			t.Fatalf("unexpected OIDC provider %q", provider["id"])
		}
	}

	flows := nestedMap(t, config, "selfservice", "flows")
	verification := requiredMap(t, flows, "verification")
	if verification["use"] != "code" || verification["notify_unknown_recipients"] != false {
		t.Fatalf(
			"verification flow = %#v, want code strategy with unknown-recipient mail disabled",
			verification,
		)
	}
	if _, present := flows["recovery"]; present {
		t.Fatalf("password recovery flow remains configured: %#v", flows["recovery"])
	}
	verificationHooks := requiredSlice(t, requiredMap(t, verification, "after"), "hooks")
	assertBlockingLifecycleHook(
		t,
		verificationHooks,
		"file:///etc/config/kratos/hooks/after-verification.jsonnet",
	)
	loginAfter := nestedMap(t, flows, "login", "after")
	if _, present := loginAfter["password"]; present {
		t.Fatalf("password login hooks remain configured: %#v", loginAfter["password"])
	}
	for _, method := range []string{"code", "passkey"} {
		hooks := requiredSlice(t, requiredMap(t, loginAfter, method), "hooks")
		assertBlockingLifecycleHook(t, hooks, "file:///etc/config/kratos/hooks/after-login.jsonnet")
	}

	registration := requiredMap(t, flows, "registration")
	if registration["login_hints"] != false {
		t.Fatalf("registration.login_hints = %#v, want false", registration["login_hints"])
	}
	registrationAfter := requiredMap(t, registration, "after")
	if _, present := registrationAfter["password"]; present {
		t.Fatalf("password registration hooks remain configured: %#v", registrationAfter["password"])
	}
	hooks := requiredSlice(t, requiredMap(t, registrationAfter, "passkey"), "hooks")
	if len(hooks) != 1 {
		t.Fatalf("passkey registration hooks = %#v, want one rejecting hook and no session", hooks)
	}
	hook := requiredObject(t, hooks[0])
	hookConfig := requiredMap(t, hook, "config")
	if hook["hook"] != "web_hook" ||
		hookConfig["body"] != "file:///etc/config/kratos/hooks/reject-credential-registration.jsonnet" {
		t.Fatalf("passkey registration hook = %#v", hook)
	}
	if _, deprecated := hookConfig["can_interrupt"]; deprecated {
		t.Fatalf("passkey registration hook uses deprecated can_interrupt")
	}
	response := requiredMap(t, hookConfig, "response")
	if response["ignore"] != false || response["parse"] != true {
		t.Fatalf("passkey registration response = %#v, want interrupting pre-persist parsing", response)
	}
	for _, method := range []string{"code", "oidc"} {
		t.Run("registration accepts "+method, func(t *testing.T) {
			hooks := requiredSlice(t, requiredMap(t, registrationAfter, method), "hooks")
			if len(hooks) != 3 {
				t.Fatalf("%s registration hooks = %#v", method, hooks)
			}
			policy := requiredObject(t, hooks[0])
			policyConfig := requiredMap(t, policy, "config")
			policyResponse := requiredMap(t, policyConfig, "response")
			if policy["hook"] != "web_hook" ||
				policyConfig["body"] != "file:///etc/config/kratos/hooks/reject-credential-registration.jsonnet" ||
				policyResponse["ignore"] != false ||
				policyResponse["parse"] != true {
				t.Fatalf("%s registration policy hook = %#v", method, policy)
			}
			lifecycle := requiredObject(t, hooks[1])
			lifecycleConfig := requiredMap(t, lifecycle, "config")
			if lifecycle["hook"] != "web_hook" ||
				lifecycleConfig["body"] != "file:///etc/config/kratos/hooks/after-registration.jsonnet" {
				t.Fatalf("%s lifecycle hook = %#v", method, lifecycle)
			}
			lifecycleResponse := requiredMap(t, lifecycleConfig, "response")
			if method == "code" {
				if lifecycleResponse["ignore"] != false {
					t.Fatalf(
						"code registration lifecycle response = %#v, want synchronous post-persist first-admin role sync",
						lifecycleResponse,
					)
				}
				if _, prePersist := lifecycleResponse["parse"]; prePersist {
					t.Fatalf(
						"code registration lifecycle response = %#v, parse would run before identity persistence",
						lifecycleResponse,
					)
				}
			} else {
				if lifecycleResponse["ignore"] != false {
					t.Fatalf(
						"OIDC registration lifecycle response = %#v, want blocking post-persist role sync before session issuance",
						lifecycleResponse,
					)
				}
				if _, prePersist := lifecycleResponse["parse"]; prePersist {
					t.Fatalf(
						"OIDC registration lifecycle response = %#v, parse would run before identity persistence",
						lifecycleResponse,
					)
				}
			}
			session := requiredObject(t, hooks[2])
			if session["hook"] != "session" {
				t.Fatalf("%s completion hook = %#v, want session", method, session)
			}
		})
	}

	settingsAfter := nestedMap(t, flows, "settings", "after")
	if _, present := settingsAfter["password"]; present {
		t.Fatalf("password settings hooks remain configured: %#v", settingsAfter["password"])
	}
	for _, method := range []string{"oidc", "passkey"} {
		hooks := requiredSlice(t, requiredMap(t, settingsAfter, method), "hooks")
		if len(hooks) != 2 {
			t.Fatalf("%s settings hooks = %#v, want pre-persist policy followed by post-persist completion", method, hooks)
		}
		for index, parse := range []bool{true, false} {
			hook := requiredObject(t, hooks[index])
			config := requiredMap(t, hook, "config")
			response := requiredMap(t, config, "response")
			if hook["hook"] != "web_hook" ||
				config["body"] != "file:///etc/config/kratos/hooks/after-settings-"+method+".jsonnet" ||
				response["ignore"] != false || response["parse"] != parse {
				t.Fatalf("%s settings hook %d = %#v, want blocking parse=%t hook", method, index, hook, parse)
			}
		}
	}
	profileHooks := requiredSlice(t, requiredMap(t, settingsAfter, "profile"), "hooks")
	if len(profileHooks) != 2 {
		t.Fatalf("profile settings hooks = %#v, want lifecycle projection followed by verification continuation", profileHooks)
	}
	profileLifecycle := requiredObject(t, profileHooks[0])
	profileLifecycleConfig := requiredMap(t, profileLifecycle, "config")
	profileLifecycleResponse := requiredMap(t, profileLifecycleConfig, "response")
	if profileLifecycle["hook"] != "web_hook" ||
		profileLifecycleConfig["body"] != "file:///etc/config/kratos/hooks/after-settings.jsonnet" ||
		profileLifecycleResponse["ignore"] != false ||
		profileLifecycleResponse["parse"] != true {
		t.Fatalf("profile settings lifecycle hook = %#v, want blocking pre-persist hook", profileLifecycle)
	}
	if hook := requiredObject(t, profileHooks[1]); hook["hook"] != "show_verification_ui" {
		t.Fatalf("profile settings completion hook = %#v, want show_verification_ui", hook)
	}
	session := nestedMap(t, config, "session", "cookie")
	if session["name"] != "${SESSION_COOKIE_NAME}" || session["path"] != "/" || session["secure"] != "true" {
		t.Fatalf("session cookie = %#v, want SESSION_COOKIE_NAME, Secure, Path=/", session)
	}
	if _, present := session["domain"]; present {
		t.Fatalf("session cookie must not set a cookie domain: %#v", session)
	}
	assertAllWebHooksUseInternalServiceSecret(t, flows)
}

func TestPasswordlessIdentitySchemaContract(t *testing.T) {
	rawSchema, err := os.ReadFile("identity.schema.json")
	if err != nil {
		t.Fatalf("read identity schema: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		t.Fatalf("decode identity schema: %v", err)
	}
	email := nestedMap(t, schema, "properties", "traits", "properties", "email")
	if email["maxLength"] != float64(254) {
		t.Fatalf("canonical email maxLength = %#v, want 254 to match API and database", email["maxLength"])
	}
	credentials := nestedMap(t, email, "ory.sh/kratos", "credentials")
	code := requiredMap(t, credentials, "code")
	if code["identifier"] != true || code["via"] != "email" {
		t.Fatalf("canonical email code credential = %#v, want email identifier", code)
	}
	passkey := requiredMap(t, credentials, "passkey")
	if passkey["display_name"] != true {
		t.Fatalf("passkey display_name = %#v, want true", passkey["display_name"])
	}
	verification := requiredMap(t, email["ory.sh/kratos"].(map[string]any), "verification")
	if verification["via"] != "email" {
		t.Fatalf("email verification = %#v, want email", verification)
	}
	pendingEmail := requiredMap(t, nestedMap(t, schema, "properties", "traits", "properties"), "pending_email")
	if pendingEmail["maxLength"] != float64(254) {
		t.Fatalf("pending email maxLength = %#v, want 254 to match API and database", pendingEmail["maxLength"])
	}
	pendingKratos := requiredMap(t, pendingEmail, "ory.sh/kratos")
	pendingVerification := requiredMap(t, pendingKratos, "verification")
	if pendingVerification["via"] != "email" {
		t.Fatalf("pending email verification = %#v, want email", pendingVerification)
	}
	if _, isCredential := pendingKratos["credentials"]; isCredential {
		t.Fatalf("pending email must not replace a sign-in credential before verification: %#v", pendingKratos)
	}
	assertNoUserFacingIdentityJargon(t, schema)
}

func TestCredentialSettingsHooksProjectFinalAndPreviousSnapshots(t *testing.T) {
	finalCredentials := map[string]any{
		"code": map[string]any{"type": "code", "identifiers": []any{"member@example.com"}},
	}
	previousCredentials := map[string]any{
		"oidc": map[string]any{"type": "oidc", "identifiers": []any{"github:subject-1"}},
		"code": map[string]any{"type": "code", "identifiers": []any{"member@example.com"}},
	}
	ctx := map[string]any{
		"flow": map[string]any{"id": "settings-flow-1", "type": "browser"},
		"identity": map[string]any{
			"id":          "identity-1",
			"credentials": finalCredentials,
		},
		"session": map[string]any{"identity": map[string]any{
			"credentials": previousCredentials,
		}},
	}
	for _, method := range []string{"oidc", "passkey"} {
		output := evaluateHook(t, "hooks/after-settings-"+method+".jsonnet", ctx)
		if output["credentials_present"] != true || output["previous_credentials_present"] != true {
			t.Fatalf("%s hook snapshot presence = %#v", method, output)
		}
		if !reflect.DeepEqual(output["credentials"], finalCredentials) ||
			!reflect.DeepEqual(output["previous_credentials"], previousCredentials) {
			t.Fatalf("%s hook snapshots = %#v, want final=%#v previous=%#v", method, output, finalCredentials, previousCredentials)
		}
	}
}

func TestAfterVerificationProjectsStagedEmailHint(t *testing.T) {
	output := evaluateHook(t, "hooks/after-verification.jsonnet", map[string]any{
		"flow": map[string]any{"id": "verification-flow-1"},
		"identity": map[string]any{
			"id": "identity-1",
			"traits": map[string]any{
				"email":         "current@example.com",
				"pending_email": "next@example.com",
			},
		},
	})

	want := map[string]any{
		"flow_id":       "verification-flow-1",
		"identity_id":   "identity-1",
		"email":         "current@example.com",
		"pending_email": "next@example.com",
	}
	if !reflect.DeepEqual(output, want) {
		t.Fatalf("after-verification projection = %#v, want %#v", output, want)
	}
}

func TestRegistrationPolicyProjectsVerificationOnlyTrait(t *testing.T) {
	output := evaluateHook(t, "hooks/reject-credential-registration.jsonnet", map[string]any{
		"flow": map[string]any{
			"id":                "registration-flow-1",
			"type":              "api",
			"active":            "code",
			"transient_payload": map[string]any{"preferred_locale": "ko"},
		},
		"identity": map[string]any{
			"id": "identity-1",
			"traits": map[string]any{
				"email":         "member@example.com",
				"pending_email": "reserved@example.com",
			},
		},
	})

	want := map[string]any{
		"flow_id":          "registration-flow-1",
		"flow_type":        "api",
		"identity_id":      "identity-1",
		"email":            "member@example.com",
		"pending_email":    "reserved@example.com",
		"method":           "code",
		"preferred_locale": "ko",
	}
	if !reflect.DeepEqual(output, want) {
		t.Fatalf("registration policy projection = %#v, want %#v", output, want)
	}
}

func TestAfterRegistrationProjectsTransientPreferredLocale(t *testing.T) {
	output := evaluateHook(t, "hooks/after-registration.jsonnet", map[string]any{
		"flow": map[string]any{
			"transient_payload": map[string]any{
				"preferred_locale": "pt-BR",
			},
		},
		"identity": map[string]any{
			"id": "identity-1",
			"traits": map[string]any{
				"email": "member@example.com",
			},
		},
	})

	want := map[string]any{
		"identity_id":      "identity-1",
		"email":            "member@example.com",
		"preferred_locale": "pt-BR",
		"trigger":          "registration",
	}
	if !reflect.DeepEqual(output, want) {
		t.Fatalf("after-registration projection = %#v, want %#v", output, want)
	}
}

func TestComposeProjectsEnvironmentSpecificPasskeyAndHookConfiguration(t *testing.T) {
	compose := readYAMLMap(t, "../../compose/identity.yml")
	environment := requiredMap(t, compose, "x-kratos-environment")
	const internalServiceSecret = "${BACKEND_TOKEN_SIGNING_SECRET:?set BACKEND_TOKEN_SIGNING_SECRET for trusted backend calls}"

	expected := map[string]string{
		"TOKEN_SIGNING_SECRET":                                                       "${BACKEND_TOKEN_SIGNING_SECRET:?set BACKEND_TOKEN_SIGNING_SECRET for trusted backend calls}",
		"SERVE_PUBLIC_CORS_ALLOWED_ORIGINS_0":                                        "${SITE_ORIGIN:?SITE_ORIGIN is required}",
		"SESSION_COOKIE_NAME":                                                        "${SESSION_COOKIE_NAME:?set SESSION_COOKIE_NAME for the shared session cookie}",
		"SESSION_COOKIE_PATH":                                                        "/",
		"SESSION_COOKIE_SECURE":                                                      "true",
		"SECURITY_ACCOUNT_ENUMERATION_MITIGATE":                                      "true",
		"SELFSERVICE_METHODS_PASSWORD_ENABLED":                                       "false",
		"SELFSERVICE_METHODS_CODE_PASSWORDLESS_ENABLED":                              "true",
		"SELFSERVICE_METHODS_CODE_CONFIG_LIFESPAN":                                   "${AUTH_CODE_LIFESPAN_SECONDS:-900}s",
		"SELFSERVICE_METHODS_CODE_CONFIG_MAX_SUBMISSIONS":                            "5",
		"SELFSERVICE_METHODS_CODE_CONFIG_MISSING_CREDENTIAL_FALLBACK_ENABLED":        "false",
		"SELFSERVICE_METHODS_LINK_ENABLED":                                           "false",
		"SELFSERVICE_METHODS_PASSKEY_CONFIG_RP_DISPLAY_NAME":                         "${KRATOS_PASSKEY_RP_DISPLAY_NAME:-Geul}",
		"SELFSERVICE_METHODS_PASSKEY_CONFIG_RP_ID":                                   "${KRATOS_PASSKEY_RP_ID:?KRATOS_PASSKEY_RP_ID is required}",
		"SELFSERVICE_METHODS_PASSKEY_CONFIG_RP_ORIGINS_0":                            "${SITE_ORIGIN:?SITE_ORIGIN is required}",
		"SELFSERVICE_DEFAULT_BROWSER_RETURN_URL":                                     "${SITE_ORIGIN:?SITE_ORIGIN is required}",
		"SELFSERVICE_ALLOWED_RETURN_URLS_0":                                          "${SITE_ORIGIN:?SITE_ORIGIN is required}",
		"SELFSERVICE_ALLOWED_RETURN_URLS_1":                                          "${SITE_ORIGIN:?SITE_ORIGIN is required}/my/security",
		"SELFSERVICE_FLOWS_LOGIN_UI_URL":                                             "${SITE_ORIGIN:?SITE_ORIGIN is required}/login",
		"SELFSERVICE_FLOWS_REGISTRATION_UI_URL":                                      "${SITE_ORIGIN:?SITE_ORIGIN is required}/login",
		"SELFSERVICE_FLOWS_LOGOUT_AFTER_DEFAULT_BROWSER_RETURN_URL":                  "${SITE_ORIGIN:?SITE_ORIGIN is required}/login",
		"SELFSERVICE_FLOWS_VERIFICATION_UI_URL":                                      "${SITE_ORIGIN:?SITE_ORIGIN is required}/verify",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_DEFAULT_BROWSER_RETURN_URL":            "${SITE_ORIGIN:?SITE_ORIGIN is required}",
		"SELFSERVICE_FLOWS_SETTINGS_UI_URL":                                          "${SITE_ORIGIN:?SITE_ORIGIN is required}/my/security",
		"SELFSERVICE_FLOWS_ERROR_UI_URL":                                             "${SITE_ORIGIN:?SITE_ORIGIN is required}/login/error",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_HOOK":                          "web_hook",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_CONFIG_METHOD":                 "POST",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_CONFIG_URL":                    "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/after-verification",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_CONFIG_BODY":                   "file:///etc/config/kratos/hooks/after-verification.jsonnet",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_CONFIG_RESPONSE_IGNORE":        "false",
		"SELFSERVICE_FLOWS_VERIFICATION_AFTER_HOOKS_0_CONFIG_RESPONSE_PARSE":         "true",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PROFILE_HOOKS_0_CONFIG_URL":                "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/after-settings",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PROFILE_HOOKS_0_CONFIG_BODY":               "file:///etc/config/kratos/hooks/after-settings.jsonnet",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PROFILE_HOOKS_0_CONFIG_RESPONSE_IGNORE":    "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PROFILE_HOOKS_0_CONFIG_RESPONSE_PARSE":     "true",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_HOOK":                         "web_hook",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_CONFIG_METHOD":                "POST",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_CONFIG_URL":                   "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/pre-settings-oidc",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_CONFIG_BODY":                  "file:///etc/config/kratos/hooks/after-settings-oidc.jsonnet",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_CONFIG_RESPONSE_IGNORE":       "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_0_CONFIG_RESPONSE_PARSE":        "true",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_HOOK":                         "web_hook",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_CONFIG_METHOD":                "POST",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_CONFIG_URL":                   "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/post-settings-oidc",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_CONFIG_BODY":                  "file:///etc/config/kratos/hooks/after-settings-oidc.jsonnet",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_CONFIG_RESPONSE_IGNORE":       "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_OIDC_HOOKS_1_CONFIG_RESPONSE_PARSE":        "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_HOOK":                      "web_hook",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_CONFIG_METHOD":             "POST",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_CONFIG_URL":                "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/pre-settings-passkey",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_CONFIG_BODY":               "file:///etc/config/kratos/hooks/after-settings-passkey.jsonnet",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_CONFIG_RESPONSE_IGNORE":    "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_0_CONFIG_RESPONSE_PARSE":     "true",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_HOOK":                      "web_hook",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_CONFIG_METHOD":             "POST",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_CONFIG_URL":                "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/post-settings-passkey",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_CONFIG_BODY":               "file:///etc/config/kratos/hooks/after-settings-passkey.jsonnet",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_CONFIG_RESPONSE_IGNORE":    "false",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PASSKEY_HOOKS_1_CONFIG_RESPONSE_PARSE":     "false",
		"SELFSERVICE_FLOWS_RECOVERY_ENABLED":                                         "false",
		"SELFSERVICE_FLOWS_REGISTRATION_AFTER_PASSKEY_HOOKS_0_CONFIG_RESPONSE_PARSE": "true",
		"SELFSERVICE_FLOWS_REGISTRATION_AFTER_CODE_HOOKS_0_CONFIG_RESPONSE_IGNORE":   "false",
		"SELFSERVICE_FLOWS_REGISTRATION_AFTER_CODE_HOOKS_0_CONFIG_RESPONSE_PARSE":    "true",
		"SELFSERVICE_FLOWS_REGISTRATION_AFTER_CODE_HOOKS_2_HOOK":                     "session",
		"SELFSERVICE_FLOWS_LOGIN_AFTER_OIDC_HOOKS_0_CONFIG_RESPONSE_PARSE":           "true",
		"SELFSERVICE_FLOWS_SETTINGS_AFTER_PROFILE_HOOKS_1_HOOK":                      "show_verification_ui",
		"SELFSERVICE_METHODS_OIDC_CONFIG_PROVIDERS_0_ACCOUNT_LINKING_MODE":           "confirm_with_existing_credential",
		"SELFSERVICE_METHODS_OIDC_CONFIG_PROVIDERS_1_ACCOUNT_LINKING_MODE":           "confirm_with_existing_credential",
	}
	for key, want := range expected {
		if environment[key] != want {
			t.Fatalf("%s = %#v, want %q", key, environment[key], want)
		}
	}
	webHookCount := 0
	for key, value := range environment {
		if !strings.HasSuffix(key, "_HOOK") || value != "web_hook" {
			continue
		}
		webHookCount++
		authValueKey := strings.TrimSuffix(key, "_HOOK") + "_CONFIG_AUTH_CONFIG_VALUE"
		if environment[authValueKey] != internalServiceSecret {
			t.Fatalf("%s = %#v, want canonical internal-service secret", authValueKey, environment[authValueKey])
		}
	}
	if webHookCount == 0 {
		t.Fatal("compose has no configured Kratos web hooks")
	}
	const courierAuthValueKey = "COURIER_HTTP_REQUEST_CONFIG_AUTH_CONFIG_VALUE"
	if environment[courierAuthValueKey] != internalServiceSecret {
		t.Fatalf("%s = %#v, want canonical internal-service secret", courierAuthValueKey, environment[courierAuthValueKey])
	}
	for key := range environment {
		if key == courierAuthValueKey || !strings.HasSuffix(key, "_CONFIG_AUTH_CONFIG_VALUE") {
			continue
		}
		hookKey := strings.TrimSuffix(key, "_CONFIG_AUTH_CONFIG_VALUE") + "_HOOK"
		if environment[hookKey] != "web_hook" {
			t.Fatalf("%s has no matching web hook at %s", key, hookKey)
		}
	}
	const rejectPasskeyKey = "SELFSERVICE_FLOWS_REGISTRATION_AFTER_PASSKEY_HOOKS_0_CONFIG_URL"
	if environment[rejectPasskeyKey] != "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/reject-credential-registration" {
		t.Fatalf("%s = %#v", rejectPasskeyKey, environment[rejectPasskeyKey])
	}
	const codeLifecycleKey = "SELFSERVICE_FLOWS_REGISTRATION_AFTER_CODE_HOOKS_1_CONFIG_URL"
	if environment[codeLifecycleKey] != "${API_INTERNAL_URL:?API_INTERNAL_URL is required}/hooks/after-login" {
		t.Fatalf("%s = %#v", codeLifecycleKey, environment[codeLifecycleKey])
	}
	if _, prePersist := environment["SELFSERVICE_FLOWS_REGISTRATION_AFTER_CODE_HOOKS_1_CONFIG_RESPONSE_PARSE"]; prePersist {
		t.Fatal("code registration hook must run after identity persistence")
	}
}

func TestCourierProjectsPasswordlessCodeContracts(t *testing.T) {
	login := evaluateHook(t, "courier/email-request.jsonnet", map[string]any{
		"recipient":     "member@example.com",
		"template_type": "login_code_valid",
		"subject":       "Your login code",
		"body":          "Use code 123456",
		"html_body":     "<p>Use code 123456</p>",
		"message_type":  "email",
		"template_data": map[string]any{
			"to":                 "member@example.com",
			"login_code":         "123456",
			"request_url":        "https://site.example/login?flow=login-flow",
			"expires_in_minutes": 15,
			"identity":           map[string]any{"id": "identity-1"},
			"transient_payload":  map[string]any{"locale": "ko"},
		},
	})
	if _, hasIdentityID := login["identityId"]; hasIdentityID {
		t.Fatalf("login courier invented unsupported identityId: %#v", login)
	}
	if _, hasFlowID := login["flowId"]; hasFlowID {
		t.Fatalf("login courier invented unsupported flowId: %#v", login)
	}
	if _, hasFlowType := login["flowType"]; hasFlowType {
		t.Fatalf("login courier invented unsupported flowType: %#v", login)
	}
	if got := sortedKeys(login); !reflect.DeepEqual(got, []string{"recipient", "templateData", "templateType"}) {
		t.Fatalf("login courier fields = %#v, want exact internal API envelope", got)
	}
	loginData := requiredMap(t, login, "templateData")
	if loginData["login_code"] != "123456" ||
		loginData["request_url"] != "https://site.example/login?flow=login-flow" ||
		loginData["expires_in_minutes"] != float64(15) {
		t.Fatalf("login courier template data = %#v", loginData)
	}

	registration := evaluateHook(t, "courier/email-request.jsonnet", map[string]any{
		"recipient":     "new@example.com",
		"template_type": "registration_code_valid",
		"subject":       "Your registration code",
		"body":          "Use code 654321",
		"html_body":     "<p>Use code 654321</p>",
		"message_type":  "email",
		"template_data": map[string]any{
			"to":                 "new@example.com",
			"registration_code":  "654321",
			"request_url":        "https://site.example/login?flow=registration-flow",
			"expires_in_minutes": 15,
			"traits":             map[string]any{"email": "new@example.com"},
			"transient_payload":  map[string]any{"preferred_locale": "en"},
		},
	})
	if _, hasIdentityID := registration["identityId"]; hasIdentityID {
		t.Fatalf("registration courier must not invent an identity ID: %#v", registration)
	}
	registrationData := requiredMap(t, registration, "templateData")
	if registrationData["registration_code"] != "654321" ||
		registrationData["request_url"] != "https://site.example/login?flow=registration-flow" ||
		registrationData["expires_in_minutes"] != float64(15) {
		t.Fatalf("registration courier template data = %#v", registrationData)
	}
	traits := requiredMap(t, registrationData, "traits")
	if !reflect.DeepEqual(traits, map[string]any{"email": "new@example.com"}) {
		t.Fatalf("registration traits = %#v", traits)
	}

	verification := evaluateHook(t, "courier/email-request.jsonnet", map[string]any{
		"recipient":     "member@example.com",
		"template_type": "verification_code_valid",
		"subject":       "Your verification code",
		"body":          "Use code 246810",
		"html_body":     "<p>Use code 246810</p>",
		"message_type":  "email",
		"template_data": map[string]any{
			"to":                 "member@example.com",
			"verification_code":  "246810",
			"request_url":        "https://site.example/verify?flow=verification-flow",
			"expires_in_minutes": 15,
			"identity":           map[string]any{"id": "identity-1"},
		},
	})
	verificationData := requiredMap(t, verification, "templateData")
	if verification["templateType"] != "verification_code_valid" ||
		verificationData["verification_code"] != "246810" ||
		verificationData["request_url"] != "https://site.example/verify?flow=verification-flow" ||
		verificationData["expires_in_minutes"] != float64(15) {
		t.Fatalf("verification courier payload = %#v", verification)
	}

	for _, templateType := range []string{
		"recovery_code_valid",
		"verification_code_invalid",
		"login_code_invalid",
		"arbitrary_template",
	} {
		t.Run("rejects "+templateType, func(t *testing.T) {
			err := evaluateHookError(t, "courier/email-request.jsonnet", map[string]any{
				"recipient":     "member@example.com",
				"template_type": templateType,
				"template_data": map[string]any{"to": "member@example.com"},
			})
			if !strings.Contains(err.Error(), "unsupported Kratos courier template selector") {
				t.Fatalf("unsupported courier template error = %v", err)
			}
			if strings.Contains(strings.ToLower(err.Error()), "recovery") {
				t.Fatalf("unsupported courier template leaked compatibility detail: %v", err)
			}
		})
	}
}

func TestRejectedCredentialRegistrationHookProjectsMethod(t *testing.T) {
	output := evaluateHook(t, "hooks/reject-credential-registration.jsonnet", map[string]any{
		"flow": map[string]any{
			"id":     "registration-flow",
			"type":   "browser",
			"active": "passkey",
		},
		"identity": map[string]any{
			"id": "identity-1",
			"traits": map[string]any{
				"email": "member@example.com",
			},
		},
	})
	if output["method"] != "passkey" || output["flow_id"] != "registration-flow" || output["identity_id"] != "identity-1" {
		t.Fatalf("passkey rejection payload = %#v", output)
	}
}

func readYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value map[string]any
	if err := yaml.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func nestedMap(t *testing.T, value map[string]any, path ...string) map[string]any {
	t.Helper()
	current := value
	for _, key := range path {
		current = requiredMap(t, current, key)
	}
	return current
}

func requiredMap(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	result, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, value[key])
	}
	return result
}

func requiredObject(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	return result
}

func requiredSlice(t *testing.T, value map[string]any, path ...string) []any {
	t.Helper()
	if len(path) == 0 {
		t.Fatal("slice path is required")
	}
	current := value
	for _, key := range path[:len(path)-1] {
		current = requiredMap(t, current, key)
	}
	key := path[len(path)-1]
	result, ok := current[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array", key, current[key])
	}
	return result
}

func assertBlockingLifecycleHook(t *testing.T, hooks []any, body string) {
	t.Helper()
	if len(hooks) != 1 {
		t.Fatalf("hooks = %#v, want one lifecycle hook", hooks)
	}
	hook := requiredObject(t, hooks[0])
	config := requiredMap(t, hook, "config")
	response := requiredMap(t, config, "response")
	if hook["hook"] != "web_hook" || config["body"] != body ||
		response["ignore"] != false || response["parse"] != true {
		t.Fatalf("lifecycle hook = %#v", hook)
	}
	if _, deprecated := config["can_interrupt"]; deprecated {
		t.Fatalf("new lifecycle hook uses deprecated can_interrupt: %#v", hook)
	}
}

func assertAllWebHooksUseInternalServiceSecret(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if typed["hook"] == "web_hook" {
			config := requiredMap(t, typed, "config")
			if _, deprecated := config["can_interrupt"]; deprecated {
				t.Fatalf("web hook retains deprecated can_interrupt: %#v", typed)
			}
			assertInternalServiceAPIKey(t, config)
		}
		for _, child := range typed {
			assertAllWebHooksUseInternalServiceSecret(t, child)
		}
	case []any:
		for _, child := range typed {
			assertAllWebHooksUseInternalServiceSecret(t, child)
		}
	}
}

func assertInternalServiceAPIKey(t *testing.T, config map[string]any) {
	t.Helper()
	auth := requiredMap(t, config, "auth")
	if auth["type"] != "api_key" {
		t.Fatalf("internal-service auth type = %#v, want api_key", auth["type"])
	}
	apiKey := requiredMap(t, auth, "config")
	if apiKey["name"] != "${INTERNAL_SERVICE_HEADER_NAME}" ||
		apiKey["value"] != "${TOKEN_SIGNING_SECRET}" ||
		apiKey["in"] != "header" {
		t.Fatalf("internal-service API key = %#v", apiKey)
	}
}

func assertStringSlice(t *testing.T, value any, expected ...string) {
	t.Helper()
	values, ok := value.([]any)
	if !ok || len(values) != len(expected) {
		t.Fatalf("value = %#v, want %#v", value, expected)
	}
	for index, want := range expected {
		if values[index] != want {
			t.Fatalf("value[%d] = %#v, want %q", index, values[index], want)
		}
	}
}

func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func evaluateHookError(t *testing.T, path string, ctx map[string]any) error {
	t.Helper()
	vm := jsonnet.MakeVM()
	vm.Importer(&jsonnet.FileImporter{JPaths: []string{"."}})
	encoded, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("encode hook context: %v", err)
	}
	vm.ExtCode("ctx", string(encoded))
	snippet := fmt.Sprintf("(import %q)(std.extVar('ctx'))", path)
	_, err = vm.EvaluateAnonymousSnippet("passwordless-contract-test.jsonnet", snippet)
	if err == nil {
		t.Fatalf("evaluate %s unexpectedly succeeded", path)
	}
	return err
}

func assertNoUserFacingIdentityJargon(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "title" {
				title, ok := child.(string)
				if !ok {
					t.Fatalf("identity schema title = %#v, want string", child)
				}
				lower := strings.ToLower(title)
				for _, forbidden := range []string{"kratos", "password", "recovery"} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("user-facing identity title %q contains internal authentication jargon", title)
					}
				}
			}
			assertNoUserFacingIdentityJargon(t, child)
		}
	case []any:
		for _, child := range typed {
			assertNoUserFacingIdentityJargon(t, child)
		}
	}
}
