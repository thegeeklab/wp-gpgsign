package gnupg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thegeeklab/wp-plugin-go/trace"
	"golang.org/x/sys/execabs"
)

var ErrGPGDirLookupFailed = errors.New("failed to lookup GPG directories")

const (
	gpgBin     = "/usr/bin/gpg"
	gpgconfBin = "/usr/bin/gpgconf"

	strictDirPerm = 0o700
)

type Client struct {
	Homedir string
	Env     []string
	Key     Key
	Version Version
	Dirs    Dirs
}

type Key struct {
	Content    string
	Passphrase string

	ID           string
	Fingerprint  string
	Identity     string
	CreationTime time.Time
}

type Version struct {
	Gnupg     string
	Libgcrypt string
}

type Dirs struct {
	Lib     string
	Libexec string
	Data    string
	Home    string
}

// New creates a new GPG client instance with the provided key and passphrase.
// It initializes the client fields and creates a temporary home directory for
// GPG operations. The home directory permissions are set to 0700 and the
// GNUPGHOME environment variable is set to point to the home directory.
func New(key, passphrase string) (*Client, error) {
	client := &Client{
		Key: Key{
			Content:    key,
			Passphrase: passphrase,
		},
		Dirs:    Dirs{},
		Version: Version{},
	}

	if err := client.SetHomedir(""); err != nil {
		return client, err
	}

	return client, nil
}

func (c *Client) SetHomedir(path string) error {
	var err error

	if path == "" {
		path, err = os.MkdirTemp("/tmp", "plugin_gpgsign_")
		if err != nil {
			return fmt.Errorf("failed to create tmp dir: %w", err)
		}

		if err := os.Chmod(path, strictDirPerm); err != nil {
			return err
		}
	} else {
		err = os.MkdirAll(path, strictDirPerm)
		if err != nil {
			return fmt.Errorf("failed to create homedir dir: %w", err)
		}
	}

	c.Homedir = path
	c.Env = append(c.Env, fmt.Sprintf("GNUPGHOME=%s", c.Homedir))

	return nil
}

// GetDirs queries gpgconf to get the GnuPG directory paths
// and populates the Dirs struct with the results. It parses
// the gpgconf output to extract the lib, libexec, data and home
// dirs.
func (c *Client) GetDirs() error {
	cmd := execabs.Command(gpgconfBin, "--list-dirs")

	cmd.Env = append(os.Environ(), c.Env...)

	output, err := cmd.Output()
	if err != nil {
		return err
	}

	res := string(output)
	if len(res) > 0 && cmd.ProcessState.ExitCode() != 0 {
		return fmt.Errorf("%w: %s", ErrGPGDirLookupFailed, res)
	}

	lines := strings.Split(strings.ReplaceAll(res, "\r", ""), "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "libdir:"):
			line = strings.TrimPrefix(line, "libdir:")
			line = strings.ReplaceAll(line, "%3a", ":")
			line = strings.TrimSpace(line)
			c.Dirs.Lib = line
		case strings.HasPrefix(line, "libexecdir:"):
			line = strings.TrimPrefix(line, "libexecdir:")
			line = strings.ReplaceAll(line, "%3a", ":")
			line = strings.TrimSpace(line)
			c.Dirs.Libexec = line
		case strings.HasPrefix(line, "datadir:"):
			line = strings.TrimPrefix(line, "datadir:")
			line = strings.ReplaceAll(line, "%3a", ":")
			line = strings.TrimSpace(line)
			c.Dirs.Data = line
		case strings.HasPrefix(line, "homedir:"):
			line = strings.TrimPrefix(line, "homedir:")
			line = strings.ReplaceAll(line, "%3a", ":")
			line = strings.TrimSpace(line)
			c.Dirs.Home = line
		}
	}

	return nil
}

// GetVersion queries gpg to get the version information
// and populates the Version struct with the results.
func (c *Client) GetVersion() (*Version, error) {
	version := &Version{}

	cmd := execabs.Command(gpgBin, "--version")

	cmd.Env = append(os.Environ(), c.Env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return version, err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "gpg (GnuPG) "):
			version.Gnupg = strings.TrimPrefix(line, "gpg (GnuPG) ")
		case strings.HasPrefix(line, "gpg (GnuPG/MacGPG2) "):
			version.Gnupg = strings.TrimPrefix(line, "gpg (GnuPG/MacGPG2) ")
		case strings.HasPrefix(line, "libgcrypt "):
			version.Libgcrypt = strings.TrimPrefix(line, "libgcrypt ")
		}
	}

	return version, nil
}

// ImportKey imports a GPG key provided via the Key.Content field.
// It runs the gpg --import command to import the key into the keyring.
// Returns an error if the import command fails.
func (c *Client) ImportKey() error {
	args := []string{
		"--batch",
		"--import",
		"-",
	}

	cmd := execabs.Command(
		gpgBin,
		args...,
	)

	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(c.Key.Content)

	trace.Cmd(cmd)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to import gpg key: %w", err)
	}

	return nil
}

// SetTrustLevel sets the trust level for the public key in the client.
// It runs the gpg --edit-key command to set the trust level to the
// provided level string. Valid levels are "undefined", "never",
// "marginal", "full", "ultimate". Returns an error if the command fails.
func (c *Client) SetTrustLevel(level string) error {
	args := []string{
		"--batch",
		"--no-tty",
		"--command-fd",
		"0",
		"--edit-key",
		c.Key.ID,
	}

	cmd := execabs.Command(
		gpgBin,
		args...,
	)

	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = bytes.NewBuffer([]byte(fmt.Sprintf("trust\n%s\ny\nquit\n", level)))

	trace.Cmd(cmd)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set trustlevel: %w", err)
	}

	return nil
}

// SignFile signs the file at the given path with the configured key.
// It supports detached, cleartext, and normal signing based on the
// detach and clear arguments.
func (c *Client) SignFile(detach, clear bool, path string) error {
	args := []string{
		"--batch",
		"--yes",
		"--armor",
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

	cmd := execabs.Command(
		gpgBin,
		args...,
	)

	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if c.Key.Passphrase != "" {
		cmd.Stdin = strings.NewReader(c.Key.Passphrase)
	}

	trace.Cmd(cmd)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	return nil
}

// Cleanup removes the home directory for the given key, if one was specified.
// It returns any error encountered while removing the directory.
func (c *Client) Cleanup() error {
	if c.Homedir != "" {
		if err := os.RemoveAll(c.Homedir); err != nil {
			return fmt.Errorf("failed to cleanup homedir %s: %w", c.Homedir, err)
		}
	}

	return nil
}
