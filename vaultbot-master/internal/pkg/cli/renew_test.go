package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert"
)

func TestExecuteRenewHook(t *testing.T) {
	p := filepath.Join(os.TempDir(), "test.gotest")
	defer os.Remove(p)
	ExecuteRenewHook(fmt.Sprintf("touch %s", p))

	_, err := os.Stat(p)
	assert.NoError(t, err, "renew-hook failed")
}
