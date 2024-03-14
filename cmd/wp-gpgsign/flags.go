// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package main

import (
	"github.com/thegeeklab/wp-gpgsign/plugin"
	"github.com/urfave/cli/v2"
)

// settingsFlags has the cli.Flags for the plugin.Settings.
//
//go:generate go run docs.go flags.go
func settingsFlags(settings *plugin.Settings, category string) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "homedir",
			Usage:       "gpg home directory",
			EnvVars:     []string{"PLUGIN_HOMEDIR", "GNUPGHOME"},
			Destination: &settings.Homedir,
			Category:    category,
		},
		&cli.StringFlag{
			Name:     "key",
			Usage:    "armored private gpg private key or the base64 encoded string of it",
			EnvVars:  []string{"PLUGIN_KEY", "GPGSIGN_KEY", "GPG_KEY"},
			Required: true,
			Category: category,
		},
		&cli.StringFlag{
			Name:        "passphrase",
			Usage:       "passphrase for the gpg private key",
			EnvVars:     []string{"PLUGIN_PASSPHRASE", "GPGSIGN_PASSPHRASE", "GPG_PASSPHRASE"},
			Destination: &settings.Passphrase,
			Category:    category,
		},
		&cli.StringFlag{
			Name:        "fingerprint",
			Usage:       "specific fingerprint to be used (subkey)",
			EnvVars:     []string{"PLUGIN_FINGERPRINT", "GPGSIGN_FINGERPRINT", "GPG_FINGERPRINT"},
			Destination: &settings.Fingerprint,
			Category:    category,
		},
		&cli.StringFlag{
			Name:        "trust-level",
			Usage:       "key owner trust level",
			EnvVars:     []string{"PLUGIN_TRUST_LEVEL"},
			Destination: &settings.TrustLevel,
			Value:       "unknown",
			Category:    category,
		},
		&cli.BoolFlag{
			Name:        "armor",
			Usage:       "create ASCII-armored output instead of a binary",
			Destination: &settings.Armor,
			Value:       false,
			EnvVars:     []string{"PLUGIN_ARMOR"},
		},
		&cli.BoolFlag{
			Name:        "detach-sign",
			Usage:       "creates a detached signature for the file",
			EnvVars:     []string{"PLUGIN_DETACH_SIGN"},
			Destination: &settings.DetachSign,
			Category:    category,
		},
		&cli.BoolFlag{
			Name:        "clear-sign",
			Usage:       "wrap the file in an ASCII-armored signature",
			EnvVars:     []string{"PLUGIN_CLEAR_SIGN"},
			Destination: &settings.ClearSign,
			Category:    category,
		},
		&cli.StringSliceFlag{
			Name:     "files",
			Usage:    "list of glob patterns to determine files to be signed",
			EnvVars:  []string{"PLUGIN_FILES", "PLUGIN_FILE"},
			Category: category,
		},
		&cli.StringSliceFlag{
			Name:     "excludes",
			Usage:    "list of glob patterns to determine files to be excluded from signing",
			EnvVars:  []string{"PLUGIN_EXCLUDES", "PLUGIN_EXCLUDE"},
			Category: category,
		},
	}
}
