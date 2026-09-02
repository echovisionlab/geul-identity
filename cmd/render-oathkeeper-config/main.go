package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/echovisionlab/geul-identity/internal/authboundary"
	"github.com/echovisionlab/geul-identity/internal/oathkeeperconfig"
)

func main() {
	templateDirectory := flag.String("template-directory", "/etc/oathkeeper-template", "directory containing generic Oathkeeper config templates")
	outputDirectory := flag.String("output-directory", "/etc/oathkeeper", "directory for rendered Oathkeeper runtime config")
	flag.Parse()

	names, err := authboundary.NamesFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "authentication boundary names:", err)
		os.Exit(1)
	}
	if err := oathkeeperconfig.Render(oathkeeperconfig.Options{
		TemplateDirectory:         *templateDirectory,
		OutputDirectory:           *outputDirectory,
		SiteOrigin:                os.Getenv("SITE_ORIGIN"),
		IssuerOrigin:              os.Getenv("MCP_OAUTH_ISSUER_URL"),
		KratosPublicURL:           os.Getenv("KRATOS_PUBLIC_URL"),
		HydraAdminURL:             os.Getenv("HYDRA_ADMIN_URL"),
		AuthorizationURL:          os.Getenv("AUTHORIZATION_URL"),
		AuthHeaderName:            names.AuthHeaderName,
		InternalServiceHeaderName: names.InternalServiceHeaderName,
		SessionCookieName:         names.SessionCookieName,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
