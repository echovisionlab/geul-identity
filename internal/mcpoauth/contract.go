package mcpoauth

import "fmt"

const (
	Scope              = "mcp"
	OfflineAccessScope = "offline_access"
	hydraClientScope   = Scope + " " + OfflineAccessScope
)

// Contract derives every public MCP OAuth URL from the deployment-owned site
// and issuer origins. Product domains never belong in reusable runtime code.
type Contract struct {
	IssuerURL                    string
	SiteOrigin                   string
	ResourceURL                  string
	ProtectedResourceMetadataURL string
}

func NewContract(issuerURL, siteOrigin string) (Contract, error) {
	issuer, err := validateUpstreamBaseURL(issuerURL)
	if err != nil {
		return Contract{}, fmt.Errorf("issuer origin: %w", err)
	}
	site, err := validateUpstreamBaseURL(siteOrigin)
	if err != nil {
		return Contract{}, fmt.Errorf("site origin: %w", err)
	}
	if issuer == site {
		return Contract{}, fmt.Errorf("issuer and site origins must differ")
	}
	return Contract{
		IssuerURL:                    issuer,
		SiteOrigin:                   site,
		ResourceURL:                  site + "/mcp",
		ProtectedResourceMetadataURL: site + "/.well-known/oauth-protected-resource/mcp",
	}, nil
}

func (c Contract) validate() error {
	expected, err := NewContract(c.IssuerURL, c.SiteOrigin)
	if err != nil {
		return err
	}
	if c != expected {
		return fmt.Errorf("MCP OAuth contract contains non-derived URLs")
	}
	return nil
}
