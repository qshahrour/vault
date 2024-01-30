package auth

import (
	"github.com/hashicorp/vault/api"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

const (
	// MethodAgent assumes the vault_addr is an agent handling authentication
	MethodAgent = "agent"
)

type AgentAuthenticater struct{}

// Authenticate does nothing, assumes agent is handling authentication
func (a *AgentAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	return nil
}
