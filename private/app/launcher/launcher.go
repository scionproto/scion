// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package launcher includes the shared application execution boilerplate of all
// SCION servers.
package launcher

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

// Configuration keys used by the launcher
const (
	cfgLogConsoleLevel           = "log.console.level"
	cfgLogConsoleFormat          = "log.console.format"
	cfgLogConsoleStacktraceLevel = "log.console.stacktrace_level"
	cfgGeneralID                 = "general.id"
	cfgConfigFile                = "config"
)

// LoggingConfig is implemented by configurations that define logging behavior.
// If a application configuration does not implement this interface, then a
// default logging configuration is used.
type LoggingConfig interface {
	// Logging returns the logging configuration. The Get prefix is used to
	// avoid collisions with data members named Logging.
	GetLogging() log.Config
}

// IDConfig is implemented by configurations that define a SCION instance ID.
// If an application configuration does not implement this interface, then the
// SCION instance ID is equal to the application binary name.
type IDConfig interface {
	// ID returns the SCION instance ID of the application. The Get prefix is
	// used to avoid collisions with data members named ID.
	GetID() string
}

// newCommandTemplate returns a cobra command template for a SCION server application.
func newCommandTemplate(executable string, shortName string, config config.Sampler,
	samplers ...func(command.Pather) *cobra.Command) *cobra.Command {

	cmd := &cobra.Command{
		Use:           executable,
		Short:         shortName,
		Example:       fmt.Sprintf("  %s --config %s", executable, "config.toml"),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
	}
	cmd.AddCommand(
		command.NewSample(
			cmd,
			append(samplers, command.NewSampleConfig(config))...,
		),
		command.NewVersion(cmd),
	)
	cmd.Flags().String(cfgConfigFile, "", "Configuration file (required)")
	cmd.MarkFlagRequired(cfgConfigFile)
	return cmd
}

func exportBuildInfo() {
	g := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scion_build_info",
			Help: "SCION build information",
		},
		[]string{"version"},
	)
	g.WithLabelValues(env.StartupVersion).Set(1)
}
