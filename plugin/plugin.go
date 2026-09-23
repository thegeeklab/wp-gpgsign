// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package plugin

import (
	"fmt"
	"slices"

	plugin_base "github.com/thegeeklab/wp-plugin-go/v7/plugin"
	"github.com/urfave/cli/v3"
)

//go:generate go run ../hack/docs-gen/main.go -output=../docs/data/data.yaml

// Plugin implements provide the plugin.
type Plugin struct {
	*plugin_base.Plugin
	Settings *Settings
}

// Settings for the plugin.
type Settings struct {
	Homedir     string
	Key         string
	Passphrase  string
	Fingerprint string
	Armor       bool
	DetachSign  bool
	ClearSign   bool
	TrustLevel  string

	setupOnly bool
	files     []string
	excludes  []string
}

func New(e plugin_base.ExecuteFunc, build ...string) *Plugin {
	p := &Plugin{
		Settings: &Settings{},
	}

	options := plugin_base.Options{
		Name:        "wp-gpgsign",
		Description: "sign artifacts with GnuPG",
		Flags: slices.Concat(
			plugin_base.LoggingFlags(plugin_base.FlagsPluginCategory),
			Flags(p.Settings, plugin_base.FlagsPluginCategory),
		),
		Execute:             p.run,
		HideWoodpeckerFlags: true,
	}

	if len(build) > 0 {
		options.Version = build[0]
	}

	if len(build) > 1 {
		options.VersionMetadata = fmt.Sprintf("date=%s", build[1])
	}

	if e != nil {
		options.Execute = e
	}

	p.Plugin = plugin_base.New(options)

	return p
}

// Flags returns a slice of CLI flags for the plugin.
func Flags(settings *Settings, category string) []cli.Flag {
	return []cli.Flag{
		// GPG home directory.
		&cli.StringFlag{
			Name:        "homedir",
			Usage:       "gpg home directory",
			Sources:     cli.EnvVars("PLUGIN_HOMEDIR", "GNUPGHOME"),
			Destination: &settings.Homedir,
			Category:    category,
		},
		// Armored private GPG private key or the base64 encoded string of it.
		&cli.StringFlag{
			Name:     "key",
			Usage:    "armored private gpg private key or the base64 encoded string of it",
			Sources:  cli.EnvVars("PLUGIN_KEY", "GPGSIGN_KEY", "GPG_KEY"),
			Required: true,
			Category: category,
		},
		// Passphrase for the GPG private key.
		&cli.StringFlag{
			Name:        "passphrase",
			Usage:       "passphrase for the gpg private key",
			Sources:     cli.EnvVars("PLUGIN_PASSPHRASE", "GPGSIGN_PASSPHRASE", "GPG_PASSPHRASE"),
			Destination: &settings.Passphrase,
			Category:    category,
		},
		// Specific fingerprint to be used. Most like this option is required if a subkey of the given
		// GPG key should be used. If not set, the fingerprint of the primary key is used.
		&cli.StringFlag{
			Name:        "fingerprint",
			Usage:       "specific fingerprint to be used (subkey)",
			Sources:     cli.EnvVars("PLUGIN_FINGERPRINT", "GPGSIGN_FINGERPRINT", "GPG_FINGERPRINT"),
			Destination: &settings.Fingerprint,
			Category:    category,
		},
		// Key owner trust level. Supported values: `unknown|never|marginal|full|ultimate`.
		&cli.StringFlag{
			Name:        "trust-level",
			Usage:       "key owner trust level",
			Sources:     cli.EnvVars("PLUGIN_TRUST_LEVEL"),
			Destination: &settings.TrustLevel,
			Value:       "unknown",
			Category:    category,
		},
		// Create ASCII-armored output instead of a binary.
		&cli.BoolFlag{
			Name:        "armor",
			Usage:       "create ASCII-armored output instead of a binary",
			Destination: &settings.Armor,
			Value:       false,
			Sources:     cli.EnvVars("PLUGIN_ARMOR"),
			Category:    category,
		},
		// Creates a detached signature for the file.
		&cli.BoolFlag{
			Name:        "detach-sign",
			Usage:       "creates a detached signature for the file",
			Sources:     cli.EnvVars("PLUGIN_DETACH_SIGN"),
			Destination: &settings.DetachSign,
			Category:    category,
		},
		// Wrap the file in an ASCII-armored signature.
		&cli.BoolFlag{
			Name:        "clear-sign",
			Usage:       "wrap the file in an ASCII-armored signature",
			Sources:     cli.EnvVars("PLUGIN_CLEAR_SIGN"),
			Destination: &settings.ClearSign,
			Category:    category,
		},
		// List of glob patterns to determine files to be signed. If the list is empty, the plugin runs in
		// setup-only mode. This is useful if the GPG key is required for other steps in the workflow.
		&cli.StringSliceFlag{
			Name:     "files",
			Usage:    "list of glob patterns to determine files to be signed",
			Sources:  cli.EnvVars("PLUGIN_FILES", "PLUGIN_FILE"),
			Category: category,
		},
		// List of glob patterns to determine files to be excluded from signing.
		&cli.StringSliceFlag{
			Name:     "excludes",
			Usage:    "list of glob patterns to determine files to be excluded from signing",
			Sources:  cli.EnvVars("PLUGIN_EXCLUDES", "PLUGIN_EXCLUDE"),
			Category: category,
		},
	}
}
