package auth

import (
	"github.com/hashicorp/vault/api"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

type Authenticater interface {
	Authenticate(options cli.Options, client *api.Client) error
}
