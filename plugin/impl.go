// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package plugin

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/thegeeklab/wp-gpgsign/gnupg"
	"github.com/thegeeklab/wp-plugin-go/file"
	"github.com/thegeeklab/wp-plugin-go/slice"
)

//nolint:revive
func (p *Plugin) run(ctx context.Context) error {
	if err := p.FlagsFromContext(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := p.Execute(); err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	return nil
}

// FlagsFromContext parses command line flags for private struct fields.
func (p *Plugin) FlagsFromContext() error {
	var err error

	rawFiles := slice.Unique(p.Context.StringSlice("files"))

	p.Settings.files, err = file.ExpandFileList(rawFiles)
	if err != nil {
		return fmt.Errorf("failed to parse files: %w", err)
	}

	rawExcludes := slice.Unique(p.Context.StringSlice("excludes"))

	p.Settings.excludes, err = file.ExpandFileList(rawExcludes)
	if err != nil {
		return fmt.Errorf("failed to parse excludes: %w", err)
	}

	p.Settings.Key = p.Context.String("key")

	if gnupg.IsArmored(p.Settings.Key) {
		return nil
	}

	byteKey, err := base64.StdEncoding.DecodeString(p.Settings.Key)
	if err != nil {
		return fmt.Errorf("failed to parse key: not armored but failed to base64 decode: %w", err)
	}

	p.Settings.Key = string(byteKey)

	return nil
}

// Validate handles the settings validation of the plugin.
func (p *Plugin) Validate() error {
	return nil
}

// Execute provides the implementation of the plugin.
func (p *Plugin) Execute() error {
	var err error

	gpgclient, err := gnupg.New(p.Settings.Key, p.Settings.Passphrase)
	if err != nil {
		return err
	}

	defer func() {
		_ = gpgclient.Cleanup()
	}()

	if len(p.Settings.files) < 1 {
		log.Info().Msg("no files found: running in setup-only mode")
	}

	if p.Settings.Homedir != "" {
		log.Debug().Msg("overwrite default homedir with plugin setting")

		if err := gpgclient.SetHomedir(p.Settings.Homedir); err != nil {
			return err
		}
	}

	// Get gpg info
	version, err := gpgclient.GetVersion()
	if err != nil {
		return err
	}

	err = gpgclient.GetDirs()
	if err != nil {
		return err
	}

	fmt.Print(
		"\nGnuPG info\n",
		fmt.Sprintf("Version    : %s (libgcrypt %s)\n", version.Gnupg, version.Libgcrypt),
		fmt.Sprintf("Libdir     : %s\n", gpgclient.Dirs.Lib),
		fmt.Sprintf("Libexecdir : %s\n", gpgclient.Dirs.Libexec),
		fmt.Sprintf("Datadir    : %s\n", gpgclient.Dirs.Data),
		fmt.Sprintf("Homedir    : %s\n", gpgclient.Dirs.Home),
		"\n",
	)

	// Read key
	if err := gpgclient.ReadPrivateKey(); err != nil {
		return err
	}

	fmt.Print(
		"GPG private key info\n",
		fmt.Sprintf("Fingerprint  : %s\n", gpgclient.Key.Fingerprint),
		fmt.Sprintf("KeyID        : %s\n", gpgclient.Key.ID),
		fmt.Sprintf("Identity     : %s\n", gpgclient.Key.Identity),
		fmt.Sprintf("CreationTime : %s\n", gpgclient.Key.CreationTime),
		"\n",
	)

	// Import key
	if err := gpgclient.ImportKey(); err != nil {
		return err
	}

	// Set key trust level
	if err := gpgclient.SetTrustLevel(p.Settings.TrustLevel); err != nil {
		return err
	}

	// Sign all given files
	for _, path := range slice.SetDifference(p.Settings.files, p.Settings.excludes, true) {
		if err := gpgclient.SignFile(p.Settings.DetachSign, p.Settings.ClearSign, path); err != nil {
			return err
		}
	}

	return nil
}
