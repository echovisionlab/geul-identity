package oathkeeperconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderRepositoryTemplates(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test file")
	}
	templateDirectory := filepath.Join(filepath.Dir(currentFile), "..", "..", "config", "oathkeeper")
	outputDirectory := t.TempDir()

	if err := Render(Options{
		TemplateDirectory:         templateDirectory,
		OutputDirectory:           outputDirectory,
		SiteOrigin:                "https://site.example",
		IssuerOrigin:              "https://sso.example",
		KratosPublicURL:           "http://kratos.example",
		HydraAdminURL:             "http://hydra.example",
		AuthorizationURL:          "http://api.example",
		AuthHeaderName:            "X-Authenticated-Context-B64",
		InternalServiceHeaderName: "X-Internal-Service",
		SessionCookieName:         "__Host-session",
	}); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outputDirectory, "oathkeeper.yml"), "https://site.example/mcp", "https://sso.example")
	assertFileContains(t, filepath.Join(outputDirectory, "rules.yml"), `https://site\.example/mcp`, "https://site.example/.well-known/oauth-protected-resource/mcp")
	assertFileContains(t, filepath.Join(outputDirectory, "oathkeeper.yml"), "X-Internal-Service", "__Host-session")
	assertFileContains(t, filepath.Join(outputDirectory, "rules.yml"), "X-Authenticated-Context-B64", "X-Internal-Service")
	for _, name := range []string{"oathkeeper.yml", "rules.yml"} {
		raw, err := os.ReadFile(filepath.Join(outputDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), templateSiteOrigin) || strings.Contains(string(raw), templateIssuerOrigin) {
			t.Errorf("%s contains an unresolved origin placeholder", name)
		}
	}
}

func TestRenderDerivesMCPContractFromOrigins(t *testing.T) {
	templateDirectory := t.TempDir()
	outputDirectory := t.TempDir()
	writeTemplate(t, templateDirectory, "oathkeeper.yml", "audience: "+templateSiteOrigin+"/mcp\nissuer: "+templateIssuerOrigin+"\nkratos: "+templateKratosPublicURL+"\nhydra: "+templateHydraAdminURL+"\nauthorization: "+templateAuthorizationURL+"\nheader: __INTERNAL_SERVICE_HEADER_NAME__\ncookie: __SESSION_COOKIE_NAME__\n")
	writeTemplate(t, templateDirectory, "rules.yml", "url: '<"+strings.ReplaceAll(templateSiteOrigin, ".", `\.`)+"/mcp>'\nresource_metadata: "+templateSiteOrigin+"/.well-known/oauth-protected-resource/mcp\nheader: __AUTH_HEADER_NAME__\ninternal: __INTERNAL_SERVICE_HEADER_NAME__\n")

	err := Render(Options{
		TemplateDirectory:         templateDirectory,
		OutputDirectory:           outputDirectory,
		SiteOrigin:                "https://site.example",
		IssuerOrigin:              "https://sso.example",
		KratosPublicURL:           "http://kratos.example",
		HydraAdminURL:             "http://hydra.example",
		AuthorizationURL:          "http://api.example",
		AuthHeaderName:            "X-Authenticated-Context-B64",
		InternalServiceHeaderName: "X-Internal-Service",
		SessionCookieName:         "__Host-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outputDirectory, "oathkeeper.yml"), "audience: https://site.example/mcp", "issuer: https://sso.example", "kratos: http://kratos.example", "hydra: http://hydra.example", "authorization: http://api.example")
	assertFileContains(t, filepath.Join(outputDirectory, "rules.yml"), `url: '<https://site\.example/mcp>'`, "resource_metadata: https://site.example/.well-known/oauth-protected-resource/mcp")
	assertFileContains(t, filepath.Join(outputDirectory, "oathkeeper.yml"), "header: X-Internal-Service", "cookie: __Host-session")
	assertFileContains(t, filepath.Join(outputDirectory, "rules.yml"), "header: X-Authenticated-Context-B64", "internal: X-Internal-Service")
}

func TestRenderRejectsInvalidOrAmbiguousContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		site   string
		issuer string
		want   string
	}{
		{name: "site path", site: "https://site.example/path", issuer: "https://sso.example", want: "SITE_ORIGIN"},
		{name: "issuer credentials", site: "https://site.example", issuer: "https://user@sso.example", want: "MCP_OAUTH_ISSUER_URL"},
		{name: "same origin", site: "https://site.example", issuer: "https://site.example", want: "must be different"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := Render(Options{
				TemplateDirectory:         t.TempDir(),
				OutputDirectory:           t.TempDir(),
				SiteOrigin:                test.site,
				IssuerOrigin:              test.issuer,
				AuthHeaderName:            "X-Authenticated-Context-B64",
				InternalServiceHeaderName: "X-Internal-Service",
				SessionCookieName:         "__Host-session",
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Render() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRenderRejectsMissingOrMalformedAuthenticationBoundaryNames(t *testing.T) {
	for _, test := range []struct {
		name     string
		auth     string
		internal string
		cookie   string
		want     string
	}{
		{name: "missing auth header", auth: "", internal: "X-Internal-Service", cookie: "__Host-session", want: "AUTH_HEADER_NAME"},
		{name: "malformed internal header", auth: "X-Authenticated-Context-B64", internal: "X Internal", cookie: "__Host-session", want: "INTERNAL_SERVICE_HEADER_NAME"},
		{name: "reserved auth header", auth: "Authorization", internal: "X-Internal-Service", cookie: "__Host-session", want: "AUTH_HEADER_NAME"},
		{name: "colliding headers", auth: "X-Context", internal: "x-context", cookie: "__Host-session", want: "must be different"},
		{name: "malformed session cookie", auth: "X-Authenticated-Context-B64", internal: "X-Internal-Service", cookie: "session; Path=/", want: "SESSION_COOKIE_NAME"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := Render(Options{
				TemplateDirectory:         t.TempDir(),
				OutputDirectory:           t.TempDir(),
				SiteOrigin:                "https://site.example",
				IssuerOrigin:              "https://sso.example",
				KratosPublicURL:           "http://kratos.example",
				HydraAdminURL:             "http://hydra.example",
				AuthorizationURL:          "http://api.example",
				AuthHeaderName:            test.auth,
				InternalServiceHeaderName: test.internal,
				SessionCookieName:         test.cookie,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Render() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRenderRejectsMissingOrInvalidServiceURLs(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "missing Kratos URL", want: "KRATOS_PUBLIC_URL"},
		{name: "Hydra URL path", want: "HYDRA_ADMIN_URL"},
		{name: "authorization URL scheme", want: "AUTHORIZATION_URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := Options{
				TemplateDirectory:         t.TempDir(),
				OutputDirectory:           t.TempDir(),
				SiteOrigin:                "https://site.example",
				IssuerOrigin:              "https://sso.example",
				KratosPublicURL:           "http://kratos.example",
				HydraAdminURL:             "http://hydra.example",
				AuthorizationURL:          "http://api.example",
				AuthHeaderName:            "X-Authenticated-Context-B64",
				InternalServiceHeaderName: "X-Internal-Service",
				SessionCookieName:         "__Host-session",
			}
			switch test.want {
			case "KRATOS_PUBLIC_URL":
				options.KratosPublicURL = ""
			case "HYDRA_ADMIN_URL":
				options.HydraAdminURL = "http://hydra.example/admin"
			case "AUTHORIZATION_URL":
				options.AuthorizationURL = "ftp://api.example"
			}
			err := Render(options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Render() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRenderRequiresEveryPlaceholder(t *testing.T) {
	templateDirectory := t.TempDir()
	writeTemplate(t, templateDirectory, "oathkeeper.yml", "issuer: "+templateIssuerOrigin+"\nkratos: "+templateKratosPublicURL+"\nhydra: "+templateHydraAdminURL+"\nauthorization: "+templateAuthorizationURL+"\nheader: __INTERNAL_SERVICE_HEADER_NAME__\ncookie: __SESSION_COOKIE_NAME__\n")
	writeTemplate(t, templateDirectory, "rules.yml", "url: '<"+strings.ReplaceAll(templateSiteOrigin, ".", `\.`)+"/mcp>'\nresource_metadata: "+templateSiteOrigin+"/.well-known/oauth-protected-resource/mcp\nheader: __AUTH_HEADER_NAME__\ninternal: __INTERNAL_SERVICE_HEADER_NAME__\n")

	err := Render(Options{
		TemplateDirectory:         templateDirectory,
		OutputDirectory:           t.TempDir(),
		SiteOrigin:                "https://site.example",
		IssuerOrigin:              "https://sso.example",
		KratosPublicURL:           "http://kratos.example",
		HydraAdminURL:             "http://hydra.example",
		AuthorizationURL:          "http://api.example",
		AuthHeaderName:            "X-Authenticated-Context-B64",
		InternalServiceHeaderName: "X-Internal-Service",
		SessionCookieName:         "__Host-session",
	})
	if err == nil || !strings.Contains(err.Error(), templateSiteOrigin+"/mcp") {
		t.Fatalf("Render() error = %v", err)
	}
}

func writeTemplate(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFileContains(t *testing.T, path string, values ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if !strings.Contains(string(raw), value) {
			t.Errorf("%s is missing %q:\n%s", path, value, raw)
		}
	}
}
