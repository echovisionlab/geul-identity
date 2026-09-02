package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/echovisionlab/geul-identity/internal/mcpoauth"
)

const (
	listenAddressEnvironment = "MCP_OAUTH_LISTEN_ADDRESS"
	hydraPublicEnvironment   = "MCP_OAUTH_HYDRA_PUBLIC_URL"
	hydraAdminEnvironment    = "MCP_OAUTH_HYDRA_ADMIN_URL"
	issuerOriginEnvironment  = "MCP_OAUTH_ISSUER_URL"
	siteOriginEnvironment    = "SITE_ORIGIN"
)

func main() {
	if err := run(); err != nil {
		log.Printf("mcp OAuth facade stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddress := os.Getenv(listenAddressEnvironment)
	if listenAddress == "" {
		listenAddress = ":8080"
	}
	hydraPublicURL, err := requiredEnvironment(hydraPublicEnvironment)
	if err != nil {
		return err
	}
	hydraAdminURL, err := requiredEnvironment(hydraAdminEnvironment)
	if err != nil {
		return err
	}
	issuerOrigin, err := requiredEnvironment(issuerOriginEnvironment)
	if err != nil {
		return err
	}
	siteOrigin, err := requiredEnvironment(siteOriginEnvironment)
	if err != nil {
		return err
	}
	contract, err := mcpoauth.NewContract(issuerOrigin, siteOrigin)
	if err != nil {
		return err
	}

	metadataResolver, err := mcpoauth.NewMetadataResolver(mcpoauth.NewSafeMetadataHTTPClient())
	if err != nil {
		return err
	}
	adminClient := internalHTTPClient(5 * time.Second)
	hydraClients, err := mcpoauth.NewHydraClientManager(hydraAdminURL, adminClient, contract)
	if err != nil {
		return err
	}
	handler, err := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		Contract:          contract,
		HydraPublicURL:    hydraPublicURL,
		HydraPublicClient: internalHTTPClient(30 * time.Second),
		MetadataResolver:  metadataResolver,
		HydraClients:      hydraClients,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          log.New(os.Stderr, "mcp-oauth-http: ", log.LstdFlags|log.LUTC),
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	log.Printf("mcp OAuth facade listening on %s", listenAddress)
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-shutdownSignal.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down MCP OAuth facade: %w", err)
		}
		if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func requiredEnvironment(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func internalHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}
