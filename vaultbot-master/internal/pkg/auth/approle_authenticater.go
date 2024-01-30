package auth

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

const (
	// MethodAppRole authenticates to vault via the AppRole backend
	MethodAppRole = "approle"
)

type AppRoleAuthenticater struct{}

// AppRole authenticates to vault via the AppRole backend
func (a *AppRoleAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	// check if necessary options are set
	if options.Vault.AppRoleRoleID == "" {
		return errors.Wrap(
			genericAuthError(options),
			"option ´vault_app_role_role_id´ must be set when using the AppRole backend",
		)
	}

	if options.Vault.AppRoleSecretID == "" {
		return errors.Wrap(
			genericAuthError(options),
			"option ´vault_app_role_secret_id´ must be set when using the AppRole backend",
		)
	}

	// authenticate to vault
	loginData := make(map[string]interface{})
	loginData["role_id"] = options.Vault.AppRoleRoleID
	loginData["secret_id"] = options.Vault.AppRoleSecretID

	resp, err := client.Logical().
		Write(fmt.Sprintf("auth/%s/login", options.Vault.AppRoleMount), loginData)
	if err != nil {
		return errors.Wrapf(
			genericAuthError(options),
			"Error authenticating to vault via AppRole backend: %s",
			err,
		)
	}

	// retrieve the token
	var token string

	if token, err = resp.TokenID(); err != nil {
		return errors.Wrapf(
			genericAuthError(options),
			"Error retrieving token after authentication to vault via AppRole authentication: %s",
			err,
		)
	}

	client.SetToken(token)
	return nil
}
