package vault

import (
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/auth"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

// RenewSelf refreshes the lease of the specified token
func RenewSelf(client *api.Client, options cli.Options) {
	responseData, err := client.Logical().Write("/auth/token/renew-self", nil)
	if err != nil {
		log.Fatalf("Unable to renew token: %s", err)
	}
	time, _ := responseData.TokenTTL()
	log.Printf("Renewed token, new ttl: %s", time)
}

// CreateClient configures the connection to vault
func CreateClient(options cli.Options) *api.Client {
	// pre parse some options
	clientTimeout, err := parseutil.ParseDurationSecond(options.Vault.ClientTimeout)
	if err != nil {
		log.Fatalf("Could not parse client_timeout: %v", options.Vault.ClientTimeout)
	}

	config := api.Config{
		Address:    options.Vault.Address,
		MaxRetries: options.Vault.MaxRetries,
		Timeout:    clientTimeout,
	}

	err = config.ConfigureTLS(&api.TLSConfig{
		CACert:        options.Vault.CACert,
		CAPath:        options.Vault.CAPath,
		ClientCert:    options.Vault.ClientCert,
		ClientKey:     options.Vault.ClientKey,
		TLSServerName: options.Vault.TLSServerName,
		Insecure:      options.Vault.Insecure,
	})
	if err != nil {
		log.Fatalf("Error configuring TLS: %s", err.Error())
	}

	client, err := api.NewClient(&config)
	if err != nil {
		log.Fatalf("Error initializing client: %s", err.Error())
	}

	var authenticater auth.Authenticater

	switch options.Vault.AuthMethod {
	case auth.MethodCert:
		authenticater = &auth.CertAuthenticater{}
	case auth.MethodToken:
		authenticater = &auth.TokenAuthenticater{}
	case auth.MethodAWSIAM:
		authenticater = &auth.AWSIAMAuthenticater{}
	case auth.MethodAWSEC2:
		authenticater = &auth.AWSEC2Authenticater{}
	case auth.MethodAppRole:
		authenticater = &auth.AppRoleAuthenticater{}
	case auth.MethodAgent:
		authenticater = &auth.AgentAuthenticater{}
	case auth.MethodGCPGCE:
		authenticater = &auth.GCPGCEAuthenticater{}
	case auth.MethodGCPIAM:
		authenticater = &auth.GCPIAMAuthenticater{}
	default:
		log.Fatalf(
			"Error: vault_auth_method should be one of [agent, cert, approle, token, aws-iam, aws-ec2, gcp-gce, gcp-iam], got: %s",
			options.Vault.AuthMethod,
		)
	}

	err = authenticater.Authenticate(options, client)
	if err != nil {
		log.Fatalf("Error during authentication: %s", err)
	}

	return client
}
