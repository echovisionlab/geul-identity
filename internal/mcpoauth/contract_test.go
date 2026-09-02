package mcpoauth

import "testing"

var testContract = func() Contract {
	contract, err := NewContract("https://sso.example", "https://site.example")
	if err != nil {
		panic(err)
	}
	return contract
}()

func TestContractDerivesPublicEndpointsFromOrigins(t *testing.T) {
	t.Parallel()
	if testContract.ResourceURL != "https://site.example/mcp" ||
		testContract.ProtectedResourceMetadataURL != "https://site.example/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("derived contract = %#v", testContract)
	}
	if _, err := NewContract("https://same.example", "https://same.example"); err == nil {
		t.Fatal("same issuer and site origin was accepted")
	}
}
