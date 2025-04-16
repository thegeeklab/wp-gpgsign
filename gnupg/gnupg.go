package gnupg

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/execabs"

	plugin_exec "github.com/thegeeklab/wp-plugin-go/v5/exec"
)

var (
	ErrDirLookupFailed   = errors.New("failed to lookup gpg directories")
	ErrInvalidTrustLevel = errors.New("invlaid key owner trust level")
	ErrGetKeygripsFailed = errors.New("failed to get keygrips")
)

const (
	gpgBin     = "/usr/bin/gpg"
	gpgconfBin = "/usr/bin/gpgconf"

	strictDirPerm  = 0o700
	strictFilePerm = 0o600
)

type Client struct {
	gpgBin      string
	gpgconfBin  string
	traceWriter io.Writer

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

// New creates a new GnuPG client with the provided key and passphrase. It sets the
// home directory for the client to the user's home directory plus ".gnupg", creating
// the directory if it does not already exist. The created client is returned along
// with any error that occurred during initialization.
func New(key, passphrase string) (*Client, error) {
	client := &Client{
		gpgBin:      gpgBin,
		gpgconfBin:  gpgconfBin,
		traceWriter: os.Stdout,
		Key: Key{
			Content:    key,
			Passphrase: passphrase,
		},
		Dirs:    Dirs{},
		Version: Version{},
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Warn().Msgf("failed to get user home dir: %s: fallback to '/root'", err)

		home = "/root"
	}

	home = filepath.Join(home, ".gnupg")

	if err := client.SetHomedir(home); err != nil {
		return client, err
	}

	return client, nil
}

// SetHomedir sets the home directory for the GnuPG client. It creates the directory
// if it does not already exist, and updates the GNUPGHOME environment variable
// for the client.
func (c *Client) SetHomedir(path string) error {
	err := os.MkdirAll(path, strictDirPerm)
	if err != nil {
		return fmt.Errorf("failed to create homedir dir: %w", err)
	}

	c.Homedir = path
	c.Env = append(c.Env, fmt.Sprintf("GNUPGHOME=%s", c.Homedir))

	return nil
}

// GetDirs retrieves the directories used by the GnuPG binary.
// It runs the `gpgconf --list-dirs` command and parses the output
// to populate the Dirs field of the Client struct.
func (c *Client) GetDirs() error {
	absBin, err := execabs.LookPath(c.gpgconfBin)
	if err != nil {
		return fmt.Errorf("could not find executable %q: %w", c.gpgconfBin, err)
	}

	cmd := plugin_exec.Command(absBin, "--list-dirs")
	cmd.Env = append(cmd.Env, c.Env...)

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

// GetVersion returns the version information for the GnuPG binary used by the Client.
// It parses the output of the `gpg --version` command to extract the version
// numbers for GnuPG and libgcrypt.
func (c *Client) GetVersion() (*Version, error) {
	version := &Version{}

	absBin, err := execabs.LookPath(c.gpgBin)
	if err != nil {
		return version, fmt.Errorf("could not find executable %q: %w", c.gpgconfBin, err)
	}

	cmd := plugin_exec.Command(absBin, "--version")
	cmd.Env = append(cmd.Env, c.Env...)

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

// Cleanup removes the GnuPG home directory if it was created by the Client.
func (c *Client) Cleanup() error {
	if c.Homedir != "" {
		if err := os.RemoveAll(c.Homedir); err != nil {
			return fmt.Errorf("failed to cleanup homedir %s: %w", c.Homedir, err)
		}
	}

	return nil
}
