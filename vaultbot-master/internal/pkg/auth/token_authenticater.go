package auth

import (
	"github.com/hashicorp/vault/api"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

// MethodToken authenticates to vault via token
const MethodToken = "token"

type TokenAuthenticater struct{}

// Authenticate to vault via token
func (t *TokenAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	client.SetToken(options.Vault.Token)
	return nil
}
