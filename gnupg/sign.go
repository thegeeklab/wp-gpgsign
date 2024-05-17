package gnupg

import (
	"fmt"
	"os"
	"strings"

	plugin_exec "github.com/thegeeklab/wp-plugin-go/v3/exec"
)

// SignFile signs the file at the given path with the configured key.
// It supports detached, cleartext, and normal signing based on the
// detach and clear arguments.
func (c *Client) SignFile(armor, detach, clear bool, path string) error {
	args := []string{
		"-u",
		fmt.Sprintf("%s!", c.Key.Fingerprint),
		"--batch",
		"--no-tty",
		"--yes",
	}

	if armor {
		args = append(args, "--armor")
	}

	if c.Key.Passphrase != "" {
		args = append(args, "--pinentry-mode", "loopback", "--passphrase-fd", "0")
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

	cmd, err := plugin_exec.Command(c.gpgBin, args...)
	if err != nil {
		return fmt.Errorf("SignFile: failed to create command: %w", err)
	}

	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.TraceWriter = c.traceWriter
	cmd.Env = append(cmd.Env, c.Env...)

	if c.Key.Passphrase != "" {
		cmd.Stdin = strings.NewReader(c.Key.Passphrase)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	return nil
}
