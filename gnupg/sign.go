package gnupg

import (
	"fmt"
	"os"

	"github.com/thegeeklab/wp-plugin-go/trace"
	"golang.org/x/sys/execabs"
)

// SignFile signs the file at the given path. It supports detached, cleartext, and normal signing.
func (c *Client) SignFile(detach, clear bool, path string) error {
	args := []string{
		"--batch",
		"--no-tty",
		"--yes",
		"--armor",
	}

	switch {
	case detach:
		args = append(args, "--detach-sign")
	case clear:
		args = append(args, "--clear-sign")
	default:
		args = append(args, "--sign")
	}

	args = append(args, path)

	cmd := execabs.Command(
		gpgBin,
		args...,
	)

	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stderr = os.Stderr

	trace.Cmd(cmd)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	return nil
}
