// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package plugin

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/thegeeklab/wp-gpgsign/gnupg"
	"github.com/thegeeklab/wp-plugin-go/v2/file"
	"github.com/thegeeklab/wp-plugin-go/v2/slice"
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

	p.Settings.files, err = expandGlobList(rawFiles)
	if err != nil {
		return fmt.Errorf("failed to parse files: %w", err)
	}

	p.Settings.setupOnly = (len(p.Settings.files) < 1)

	rawExcludes := slice.Unique(p.Context.StringSlice("excludes"))

	p.Settings.excludes, err = expandGlobList(rawExcludes)
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

	if p.Settings.setupOnly {
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

	log.Info().Msgf("read private key and environment metadata")

	fmt.Print(
		"GnuPG info\n",
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
	)

	if p.Settings.Fingerprint != "" {
		gpgclient.Key.Fingerprint = p.Settings.Fingerprint
	}

	log.Info().Str("fingerprint", gpgclient.Key.Fingerprint).
		Msg("use fingerprint")

	// Import key
	log.Info().Msg("import private key")

	if err := gpgclient.ImportKey(); err != nil {
		return err
	}

	// Set key owner trust
	log.Info().Str("trustlevel", p.Settings.TrustLevel).
		Msg("set key owner trust")

	if err := gpgclient.SetTrustLevel(p.Settings.TrustLevel); err != nil {
		return err
	}

	// Exit early in setup-only mode
	if p.Settings.setupOnly {
		return nil
	}

	// Sign all given files
	for i, path := range slice.SetDifference(p.Settings.files, p.Settings.excludes, true) {
		if i == 0 {
			log.Info().Msg("sign files")
		}

		if err := gpgclient.SignFile(p.Settings.Armor, p.Settings.DetachSign, p.Settings.ClearSign, path); err != nil {
			return err
		}
	}

	return nil
}

// expandGlobList expands a list of file globs into a list of individual file paths.
// It filters the results to only include regular files.
func expandGlobList(fileList []string) ([]string, error) {
	result := make([]string, 0)

	files, err := file.ExpandFileList(fileList)
	if err != nil {
		return result, err
	}

	for _, f := range files {
		fs, _ := os.Stat(f)
		if fs.Mode().IsRegular() {
			result = append(result, f)
		}
	}

	return result, err
}
