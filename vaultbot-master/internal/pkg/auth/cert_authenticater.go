package auth

import (
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

const (
	// MethodCert authenticates to vault via client cert
	MethodCert = "cert"
)

type CertAuthenticater struct{}

// Authenticate to vault via the cert auth backend
func (c *CertAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	// check if necessary options are set
	if options.Vault.ClientCert == "" {
		return errors.Wrap(
			genericAuthError(options),
			"option ´vault_client_cert´ must be set when using the Cert backend",
		)
	}

	if options.Vault.ClientKey == "" {
		return errors.Wrap(
			genericAuthError(options),
			"option ´vault_client_key´ must be set when using the Cert backend",
		)
	}

	loginData := make(map[string]interface{})
	if options.Vault.CertificateRole == "" {
		loginData = nil
	} else {
		loginData["name"] = options.Vault.CertificateRole
	}

	resp, err := client.Logical().Write("auth/cert/login", loginData)
	if err != nil {
		return errors.Wrap(
			genericAuthError(options),
			"Error authenticating to vault via Cert backend: %s",
		)
	}

	// retrieve the token
	var token string

	if token, err = resp.TokenID(); err != nil {
		return errors.Wrap(
			genericAuthError(options),
			"Error retrieving token after authentication to vault via Cert authentication: %s",
		)
	}

	client.SetToken(token)
	return nil
}
