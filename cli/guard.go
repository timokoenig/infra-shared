package cli

import (
	"errors"

	"github.com/timokoenig/infra-shared/token"
)

// GuardError maps a token guard error to the exit code every tool uses:
// an approval that is still pending is exit 3 (there is something to look
// at), everything else is exit 1.
func GuardError(err error) error {
	var ar *token.ErrApprovalRequired
	if errors.As(err, &ar) {
		return Problems(err.Error())
	}
	return Failed(err.Error())
}
