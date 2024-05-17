package gnupg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/thegeeklab/wp-plugin-go/v3/trace"
	"golang.org/x/sys/execabs"
)

var (
	ErrPrimaryIdentityNotFound = errors.New("no primary identity found")
	ErrReadKeyFailed           = errors.New("failed to read private key")
)

// IsArmored checks if the given key is armored by trying to parse it.
// Returns true if the key is armored, false otherwise.
func IsArmored(key string) bool {
	_, err := crypto.NewKeyFromArmored(key)

	return err == nil
}

// ReadPrivateKey reads a private key from the given Key struct.
// It parses the armored key content into a gopenpgp private key.
// It returns the key ID, creation time, identity, and fingerprint.
// It returns an error if the key could not be parsed or the primary identity was not found.
func (c *Client) ReadPrivateKey() error {
	gkey, err := crypto.NewKeyFromArmored(c.Key.Content)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}

	entity := gkey.GetEntity()
	primary := entity.PrimaryKey

	c.Key.ID = primary.KeyIdString()
	c.Key.CreationTime = primary.CreationTime.UTC()
	c.Key.Identity = entity.PrimaryIdentity().Name
	c.Key.Fingerprint = strings.ToUpper(hex.EncodeToString(primary.Fingerprint))

	if c.Key.Identity == "" {
		return ErrPrimaryIdentityNotFound
	}

	return nil
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
// provided level string. Valid levels are "unknown", "never", "marginal",
// "full", "ultimate". Returns an error if the command fails.
func (c *Client) SetTrustLevel(level string) error {
	valid := []string{"unknown", "never", "marginal", "full", "ultimate"}

	if !slices.Contains(valid, level) {
		return fmt.Errorf("%w: %s", ErrInvalidTrustLevel, level)
	}

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
		return fmt.Errorf("failed to set key owner trust: %w", err)
	}

	return nil
}
