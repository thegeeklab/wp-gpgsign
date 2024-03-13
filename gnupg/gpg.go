package gnupg

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/execabs"
)

var (
	ErrDirLookupFailed    = errors.New("failed to lookup gpg directories")
	ErrInvalidTrustLevel  = errors.New("invlaid key owner trust level")
	ErrAgentSetupFailed   = errors.New("gpg agent setup failed")
	ErrAgentCommandFailed = errors.New("gpg agent command failed")
	ErrGetKeygripsFailed  = errors.New("failed to get keygrips")
)

const (
	gpgBin             = "/usr/bin/gpg"
	gpgconfBin         = "/usr/bin/gpgconf"
	gpgAgentBin        = "/usr/bin/gpg-agent"
	gpgConnectAgentBin = "/usr/bin/gpg-connect-agent"

	strictDirPerm  = 0o700
	strictFilePerm = 0o600
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

// New creates a new Client instance with the given private key and passphrase.
func New(key, passphrase string) (*Client, error) {
	client := &Client{
		Key: Key{
			Content:    key,
			Passphrase: passphrase,
		},
		Dirs:    Dirs{},
		Version: Version{},
	}

	home := "/root"

	if currentUser, err := user.Current(); err == nil {
		home = currentUser.HomeDir
	}

	home = filepath.Join(home, ".gnupg")

	if err := client.SetHomedir(home); err != nil {
		return client, err
	}

	return client, nil
}

// SetHomedir sets the home directory path for the GPG client.
// It creates the directory if it doesn't exist and sets the
// GNUPGHOME environment variable to point to it.
func (c *Client) SetHomedir(path string) error {
	err := os.MkdirAll(path, strictDirPerm)
	if err != nil {
		return fmt.Errorf("failed to create homedir dir: %w", err)
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

	out, err := cmd.Output()
	if err != nil {
		return err
	}

	res := string(out)
	if len(res) > 0 && cmd.ProcessState.ExitCode() != 0 {
		return fmt.Errorf("%w: %s", ErrDirLookupFailed, res)
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

	out, err := cmd.CombinedOutput()
	if err != nil {
		return version, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
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
