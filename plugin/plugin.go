// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package plugin

import (
	wp "github.com/thegeeklab/wp-plugin-go/plugin"
)

// Plugin implements provide the plugin.
type Plugin struct {
	*wp.Plugin
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

func New(options wp.Options, settings *Settings) *Plugin {
	p := &Plugin{}

	options.Execute = p.run

	p.Plugin = wp.New(options)
	p.Settings = settings

	return p
}
