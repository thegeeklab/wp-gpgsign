package gnupg

import (
	"fmt"
	"os"
	"strings"

	"github.com/thegeeklab/wp-plugin-go/v2/types"
	"golang.org/x/sys/execabs"
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

	bin, err := execabs.LookPath(c.gpgBin)
	if err != nil {
		return fmt.Errorf("failed to find gpg binary: %w", err)
	}

	cmd := types.Cmd{
		Cmd:         execabs.Command(bin, args...),
		Private:     true,
		TraceWriter: c.traceWriter,
	}

	cmd.Env = append(os.Environ(), c.Env...)

	if c.Key.Passphrase != "" {
		cmd.Stdin = strings.NewReader(c.Key.Passphrase)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	return nil
}
