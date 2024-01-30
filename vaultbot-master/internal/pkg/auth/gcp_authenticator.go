package auth

import (
	"context"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/gcp"
	"github.com/pkg/errors"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

const (
	// MethodGCPGCE is the GCP GCE authentication method
	MethodGCPGCE = "gcp-gce"

	// MethodGCPIAM is the GCP IAM authentication method
	MethodGCPIAM = "gcp-iam"
)

// gcpAuth performs gcp authentiation using the selected method
func gcpAuth(options cli.Options, client *api.Client, method string) error {
	// build login options specific to the method
	opts := []gcp.LoginOption{
		gcp.WithMountPath(options.Vault.GCPAuthMount),
	}

	switch method {
	case MethodGCPIAM:
		opts = append(opts, gcp.WithIAMAuth(options.Vault.GCPAuthServiceAccountEmail))
	case MethodGCPGCE:
		opts = append(opts, gcp.WithGCEAuth())
	default:
		return errors.Wrapf(genericAuthError(options), "Invalid gcp auth method: %s", method)
	}

	// build an auth client
	gcpauth, err := gcp.NewGCPAuth(options.Vault.GCPAuthRole, opts...)
	if err != nil {
		return errors.Wrapf(genericAuthError(options), err.Error())
	}

	// perform the login
	resp, err := gcpauth.Login(context.Background(), client)
	if err != nil {
		return errors.Wrapf(genericAuthError(options), err.Error())
	}

	// retrieve the token
	token, err := resp.TokenID()
	if err != nil {
		return errors.Wrapf(
			genericAuthError(options),
			"Error retrieving token after authentication to vault via %s authentication: %s",
			method,
			err,
		)
	}

	client.SetToken(token)
	return nil
}

// GCPGCEAuthenticater authenticates into GCP using GCE metadata auth
type GCPGCEAuthenticater struct{}

// Authenticate authenticates using GCE metadata auth
func (a *GCPGCEAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	return gcpAuth(options, client, MethodGCPGCE)
}

// GCPIAMAuthenticater authenticates into GCP using IAM auth
type GCPIAMAuthenticater struct{}

// Authenticate authenticates using IAM auth
func (a *GCPIAMAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	return gcpAuth(options, client, MethodGCPIAM)
}
