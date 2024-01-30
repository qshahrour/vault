package auth

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

// CheckAuthentication verifies that the connection to vault is setup correctly by retrieving information about the configured token
func CheckAuthentication(client *api.Client) error {
	tokenInfo, tokenErr := client.Auth().Token().LookupSelf()
	if tokenErr != nil {
		return fmt.Errorf("Error connecting to vault: %s", tokenErr)
	}

	tokenPolicies, polErr := tokenInfo.TokenPolicies()
	if polErr != nil {
		return fmt.Errorf("Error looking up token policies: %s", tokenErr)
	}
	log.Printf("Successfully authenticated to vault. Got token policies: %s", tokenPolicies)
	return nil
}

func genericAuthError(options cli.Options) error {
	return fmt.Errorf("Error authenticating via %s", options.Vault.AuthMethod)
}
