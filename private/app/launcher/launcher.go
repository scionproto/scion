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
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
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

// ApplicationBase provides common launcher functions for a SCION server application.
type ApplicationBase struct {
	// TOMLConfig holds the Go data structure for the application-specific
	// TOML configuration. The Application launcher will check if the TOMLConfig
	// supports additional methods (e.g., custom logging or instance ID) and
	// extract them from the config if that is the case. See the XxxConfig interfaces
	// in this package for more information.
	TOMLConfig config.Config

	// Samplers contains additional configuration samplers to be included
	// under the sample subcommand. If empty, no additional samplers are
	// listed.
	//
	// DEPRECATED. This field will be removed once Anapaya/scion#5000 is implemented.
	Samplers []func(command.Pather) *cobra.Command

	// ShortName is the short name of the application. If empty, the executable name is used.
	// The ShortName could be, for example, "SCION Daemon" for the SCION Daemon.
	ShortName string

	// RequiredIPs should return the IPs that this application wants to listen
	// on. The launcher will wait until those IPs can be listened on. The
	// function is called after the configuration has been  initialized. If this
	// function is not set the launcher will immediately start the application
	// without waiting for any IPs.
	RequiredIPs func() ([]net.IP, error)

	// Main is the custom logic of the application. If nil, no custom logic is executed
	// (and only the setup/teardown harness runs). If Main returns an error, the
	// Run method will return a non-zero exit code.
	Main func(ctx context.Context) error

	// ErrorWriter specifies where error output should be printed. If nil, os.Stderr is used.
	ErrorWriter io.Writer

	// config contains the Viper configuration KV store.
	config *viper.Viper
}

func (a *ApplicationBase) getShortName(executable string) string {
	if a.ShortName != "" {
		return a.ShortName
	}
	return executable
}

func (a *ApplicationBase) loadConfig() error {
	os.Setenv("TZ", "UTC")

	// Load launcher configurations from the same config file as the custom
	// application configuration.
	a.config.SetConfigType("toml")
	a.config.SetConfigFile(a.config.GetString(cfgConfigFile))
	if err := a.config.ReadInConfig(); err != nil {
		return serrors.Wrap("loading generic server config from file", err,
			"file", a.config.GetString(cfgConfigFile))

	}

	if err := config.LoadFile(a.config.GetString(cfgConfigFile), a.TOMLConfig); err != nil {
		return serrors.Wrap("loading config from file", err,
			"file", a.config.GetString(cfgConfigFile))

	}
	a.TOMLConfig.InitDefaults()
	return nil
}

func (a *ApplicationBase) initLogging() error {
	logEntriesTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "lib_log_emitted_entries_total",
			Help: "Total number of log entries emitted.",
		},
		[]string{"level"},
	)
	opt := log.WithEntriesCounter(log.EntriesCounter{
		Debug: logEntriesTotal.With(prometheus.Labels{"level": "debug"}),
		Info:  logEntriesTotal.With(prometheus.Labels{"level": "info"}),
		Error: logEntriesTotal.With(prometheus.Labels{"level": "error"}),
	})
	if err := log.Setup(a.getLogging(), opt); err != nil {
		return serrors.Wrap("initialize logging", err)
	}
	return nil
}

func (a *ApplicationBase) executeCommand(ctx context.Context, shortName string) error {

	defer log.Flush()
	if a.RequiredIPs != nil {
		ips, err := a.RequiredIPs()
		if err != nil {
			return serrors.Wrap("loading required IPs", err)
		}
		WaitForNetworkReady(ctx, ips)
	}
	if err := env.LogAppStarted(shortName, a.config.GetString(cfgGeneralID)); err != nil {
		return err
	}
	defer env.LogAppStopped(shortName, a.config.GetString(cfgGeneralID))
	defer log.HandlePanic()

	exportBuildInfo()
	prom.ExportElementID(a.config.GetString(cfgGeneralID))
	if err := a.TOMLConfig.Validate(); err != nil {
		return serrors.Wrap("validate config", err)
	}

	if a.Main == nil {
		return nil
	}
	return a.Main(ctx)
}

func (a *ApplicationBase) getLogging() log.Config {
	return log.Config{
		Console: log.ConsoleConfig{
			Level:           a.config.GetString(cfgLogConsoleLevel),
			Format:          a.config.GetString(cfgLogConsoleFormat),
			StacktraceLevel: a.config.GetString(cfgLogConsoleStacktraceLevel),
		},
	}
}

func (a *ApplicationBase) getErrorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

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
