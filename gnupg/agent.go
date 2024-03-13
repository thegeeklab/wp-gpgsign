package gnupg

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/thegeeklab/wp-plugin-go/trace"
	"golang.org/x/sys/execabs"
)

const agentConfig = `default-cache-ttl 21600
max-cache-ttl 31536000
allow-preset-passphrase`

// GetKeygrips retrieves the keygrip for the Client's private key.
// If fingerprintOnly is true, it will return just the first keygrip
// matching the fingerprint. If false, it will return all keygrips.
func (c *Client) GetKeygrips(fingerprintOnly bool) ([]string, error) {
	var (
		keygrips         []string
		fingerprintFound bool
	)

	args := []string{
		"--batch",
		"--with-colons",
		"--with-keygrip",
		"--list-secret-keys",
		c.Key.Fingerprint,
	}

	cmd := execabs.Command(
		gpgBin,
		args...,
	)

	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stderr = os.Stderr

	trace.Cmd(cmd)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetKeygripsFailed, err)
	}

	if !fingerprintOnly {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasPrefix(line, "grp") {
				keygrips = append(keygrips, strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(line, "grp", ""), ":", "")))
			}
		}

		return keygrips, nil
	}

	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(out), "\r", "")), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "fpr:") && strings.Contains(line, fmt.Sprintf(":%s:", c.Key.Fingerprint)) {
			// We reach the record with the matching fingerprint.
			// The next keygrip record is the keygrip for this fingerprint.
			fingerprintFound = true

			continue
		}

		if strings.HasPrefix(line, "grp:") && fingerprintFound {
			keygrips = append(keygrips, strings.TrimSpace(strings.ReplaceAll(line, "grp", "")))

			break
		}
	}

	return keygrips, nil
}

// PresetPassphrase sets the passphrase for the key with the given keygrip.
// It connects to the gpg-agent to provide the passphrase, then calls KEYINFO
// to sync the passphrase status. Returns any error from the gpg-agent commands.
// This allows pre-providing a passphrase before using the key, so prompts are avoided.
func (c *Client) PresetPassphrase(keygrip string) error {
	if c.Key.Passphrase == "" {
		return nil
	}

	hexPassphrase := strings.ToUpper(hex.EncodeToString([]byte(c.Key.Passphrase)))

	if err := c.connectAgent(fmt.Sprintf("PRESET_PASSPHRASE %s -1 %s", keygrip, hexPassphrase)); err != nil {
		return err
	}

	if err := c.connectAgent("KEYINFO " + keygrip); err != nil {
		return err
	}

	return nil
}

// StartAgent starts the gpg-agent daemon process.
func (c *Client) StartAgent() error {
	cmd := execabs.Command(gpgAgentBin, "--daemon")

	trace.Cmd(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start gpg-agent: %w", err)
	}

	agentConf := filepath.Join(c.Homedir, "gpg-agent.conf")
	log.Debug().Msgf("write gpg config to '%s'", agentConf)

	if err := os.WriteFile(agentConf, []byte(agentConfig), strictFilePerm); err != nil {
		return fmt.Errorf("%w: %w", ErrAgentSetupFailed, err)
	}

	if err := c.connectAgent("RELOADAGENT"); err != nil {
		return err
	}

	return nil
}

// connectAgent executes the given command against the gpg-agent
// and returns any error.
func (c *Client) connectAgent(command string) error {
	cmd := exec.Command(gpgConnectAgentBin, command, "/bye")

	cmd.Env = append(os.Environ(), c.Env...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug().Msg(string(out))

		return fmt.Errorf("%w: %w", ErrAgentCommandFailed, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ERR") {
			return fmt.Errorf("%w: %s", ErrAgentCommandFailed, line)
		}
	}

	return nil
}
