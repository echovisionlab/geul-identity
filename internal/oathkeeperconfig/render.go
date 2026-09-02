package oathkeeperconfig

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/echovisionlab/geul-identity/internal/authboundary"
)

const (
	templateSiteOrigin       = "https://site.example.invalid"
	templateIssuerOrigin     = "https://sso.example.invalid"
	templateKratosPublicURL  = "__KRATOS_PUBLIC_URL__"
	templateHydraAdminURL    = "__HYDRA_ADMIN_URL__"
	templateAuthorizationURL = "__AUTHORIZATION_URL__"
)

type Options struct {
	TemplateDirectory         string
	OutputDirectory           string
	SiteOrigin                string
	IssuerOrigin              string
	KratosPublicURL           string
	HydraAdminURL             string
	AuthorizationURL          string
	AuthHeaderName            string
	InternalServiceHeaderName string
	SessionCookieName         string
}

func Render(options Options) error {
	siteOrigin, err := validateOrigin("SITE_ORIGIN", options.SiteOrigin)
	if err != nil {
		return err
	}
	issuerOrigin, err := validateOrigin("MCP_OAUTH_ISSUER_URL", options.IssuerOrigin)
	if err != nil {
		return err
	}
	if siteOrigin == issuerOrigin {
		return fmt.Errorf("SITE_ORIGIN and MCP_OAUTH_ISSUER_URL must be different origins")
	}
	kratosPublicURL, err := validateOrigin("KRATOS_PUBLIC_URL", options.KratosPublicURL)
	if err != nil {
		return err
	}
	hydraAdminURL, err := validateOrigin("HYDRA_ADMIN_URL", options.HydraAdminURL)
	if err != nil {
		return err
	}
	authorizationURL, err := validateOrigin("AUTHORIZATION_URL", options.AuthorizationURL)
	if err != nil {
		return err
	}
	authNames, err := authboundary.NewNames(
		options.AuthHeaderName,
		options.InternalServiceHeaderName,
		options.SessionCookieName,
	)
	if err != nil {
		return fmt.Errorf("authentication boundary names: %w", err)
	}

	templateDirectory := strings.TrimSpace(options.TemplateDirectory)
	outputDirectory := strings.TrimSpace(options.OutputDirectory)
	if templateDirectory == "" || outputDirectory == "" {
		return fmt.Errorf("template and output directories are required")
	}
	templateDirectory, err = filepath.Abs(templateDirectory)
	if err != nil {
		return fmt.Errorf("resolve template directory: %w", err)
	}
	outputDirectory, err = filepath.Abs(outputDirectory)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	if templateDirectory == outputDirectory {
		return fmt.Errorf("template and output directories must be different")
	}

	if err := os.MkdirAll(outputDirectory, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := renderFile(
		filepath.Join(templateDirectory, "oathkeeper.yml"),
		filepath.Join(outputDirectory, "oathkeeper.yml"),
		map[string]string{
			templateSiteOrigin + "/mcp":                       siteOrigin + "/mcp",
			templateIssuerOrigin:                              issuerOrigin,
			templateKratosPublicURL:                           kratosPublicURL,
			templateHydraAdminURL:                             hydraAdminURL,
			templateAuthorizationURL:                          authorizationURL,
			authboundary.InternalServiceHeaderNamePlaceholder: authNames.InternalServiceHeaderName,
			authboundary.SessionCookieNamePlaceholder:         authNames.SessionCookieName,
		},
	); err != nil {
		return err
	}
	if err := renderFile(
		filepath.Join(templateDirectory, "rules.yml"),
		filepath.Join(outputDirectory, "rules.yml"),
		map[string]string{
			regexp.QuoteMeta(templateSiteOrigin):              regexp.QuoteMeta(siteOrigin),
			templateSiteOrigin:                                siteOrigin,
			authboundary.AuthHeaderNamePlaceholder:            authNames.AuthHeaderName,
			authboundary.InternalServiceHeaderNamePlaceholder: authNames.InternalServiceHeaderName,
		},
	); err != nil {
		return err
	}
	return nil
}

func validateOrigin(name, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%s must be an exact HTTP(S) origin: %w", name, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("%s must be an exact HTTP(S) origin", name)
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must not contain a path, query, or fragment", name)
	}
	if parsed.String() != value {
		return "", fmt.Errorf("%s must be canonical", name)
	}
	return value, nil
}

func renderFile(sourcePath, outputPath string, replacements map[string]string) error {
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sourcePath, err)
	}
	contents := string(raw)
	placeholders := make([]string, 0, len(replacements))
	for placeholder := range replacements {
		placeholders = append(placeholders, placeholder)
	}
	sort.Slice(placeholders, func(i, j int) bool {
		return len(placeholders[i]) > len(placeholders[j])
	})
	for _, placeholder := range placeholders {
		replacement := replacements[placeholder]
		if strings.Count(contents, placeholder) == 0 {
			return fmt.Errorf("%s is missing required placeholder %q", sourcePath, placeholder)
		}
		contents = strings.ReplaceAll(contents, placeholder, replacement)
	}
	if strings.Contains(contents, templateSiteOrigin) || strings.Contains(contents, templateIssuerOrigin) {
		return fmt.Errorf("%s contains an unresolved origin placeholder", sourcePath)
	}
	for _, placeholder := range []string{
		templateKratosPublicURL,
		templateHydraAdminURL,
		templateAuthorizationURL,
	} {
		if strings.Contains(contents, placeholder) {
			return fmt.Errorf("%s contains an unresolved service URL placeholder %q", sourcePath, placeholder)
		}
	}
	for _, placeholder := range []string{
		authboundary.AuthHeaderNamePlaceholder,
		authboundary.InternalServiceHeaderNamePlaceholder,
		authboundary.SessionCookieNamePlaceholder,
	} {
		if strings.Contains(contents, placeholder) {
			return fmt.Errorf("%s contains an unresolved authentication boundary placeholder %q", sourcePath, placeholder)
		}
	}

	temporaryFile, err := os.CreateTemp(filepath.Dir(outputPath), ".oathkeeper-render-*")
	if err != nil {
		return fmt.Errorf("create temporary output for %s: %w", outputPath, err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)
	if err := temporaryFile.Chmod(0o640); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("set permissions for %s: %w", outputPath, err)
	}
	if _, err := temporaryFile.WriteString(contents); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outputPath, err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("publish %s: %w", outputPath, err)
	}
	return nil
}
