// Copyright (c) 2024, Robert Kaussow <mail@thegeeklab.de>

// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thegeeklab/wp-gpgsign/plugin"

	wp "github.com/thegeeklab/wp-plugin-go/v3/plugin"
)

//nolint:gochecknoglobals
var (
	BuildVersion = "devel"
	BuildDate    = "00000000"
)

func main() {
	settings := &plugin.Settings{}

	options := wp.Options{
		Name:            "wp-gpgsign",
		Description:     "sign artifacts with GnuPG",
		Version:         BuildVersion,
		VersionMetadata: fmt.Sprintf("date=%s", BuildDate),
		Flags:           settingsFlags(settings, wp.FlagsPluginCategory),
	}

	plugin.New(options, settings).Run()
}
