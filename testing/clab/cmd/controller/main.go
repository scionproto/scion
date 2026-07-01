// Copyright 2026 Anapaya Systems
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

// Controller is the PID 1 init and process supervisor for a SCION containerlab
// node (one ISD-AS per node).
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
)

func main() {
	executable := filepath.Base(os.Args[0])

	var flags struct {
		configDir       string
		configFile      string
		binDir          string
		logDir          string
		dataDir         string
		statusFile      string
		shutdownTimeout time.Duration
	}

	cmd := &cobra.Command{
		Use:   executable,
		Short: "SCION containerlab node controller",
		Long: executable + ` is the PID 1 init and process supervisor for a SCION
containerlab node (one ISD-AS per node).

It reads the generalized configuration, renders it into the per-service SCION
configuration files, launches the dispatcher, router, control, and daemon
processes, reaps children (including reparented orphans), restarts crashed
services with backoff, and shuts everything down cleanly on SIGTERM/SIGINT.

The interface addressing and the set of services are both derived from the
configuration at start time; there is no configuration API yet.`,
		Args: cobra.NoArgs,
		// Errors and usage are handled in main; don't let cobra print usage on
		// a runtime error from RunE.
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return run(flags.configDir, flags.configFile, flags.binDir, flags.logDir,
				flags.dataDir, flags.statusFile, flags.shutdownTimeout)
		},
	}

	// Inputs the list subcommands share with the controller are persistent so
	// they are inherited by every subcommand; run-only knobs stay local.
	cmd.PersistentFlags().StringVar(&flags.configDir, "config-dir",
		envOr("SCION_CONFIG_DIR", "/etc/scion"),
		"directory holding the bind-mounted crypto material and where the rendered "+
			"service configs are written",
	)
	cmd.PersistentFlags().StringVar(&flags.configFile, "config-file",
		envOr("SCION_CONFIG_FILE", "/etc/scion/config.yml"),
		"path to the generalized configuration (YAML or JSON) for this node",
	)
	cmd.PersistentFlags().StringVar(&flags.binDir, "bin-dir", envOr("SCION_BIN_DIR", "/app"),
		"directory holding the SCION service binaries",
	)
	cmd.PersistentFlags().StringVar(&flags.statusFile, "status-file",
		envOr("SCION_STATUS_FILE", "/var/run/scion/status.json"),
		"file the controller writes live service status to (read by `list services`)",
	)
	cmd.Flags().StringVar(&flags.logDir, "log-dir", envOr("SCION_LOG_DIR", "/var/log/scion"),
		"directory for per-service log files; empty disables them (output still goes to stdout)",
	)
	cmd.Flags().StringVar(&flags.dataDir, "data-dir", envOr("SCION_DATA_DIR", "/var/lib/scion"),
		"directory created at startup for service databases; empty disables creation",
	)
	cmd.Flags().DurationVar(&flags.shutdownTimeout, "shutdown-timeout", 10*time.Second,
		"grace period for services to stop on shutdown before SIGKILL",
	)

	servicesCmd := &cobra.Command{
		Use:   "services",
		Short: "Inspect the node's SCION services",
		Args:  cobra.NoArgs,
	}
	servicesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the SCION services and their live status",
		Long: `List the SCION services and their live status (running, PID, restarts,
last exit), as published by the running controller to the status file.

If the status file is absent — the controller is not running — this falls back
to the static set of services rendered from configuration.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			out := cmd.OutOrStdout()
			statuses, err := readStatusFile(flags.statusFile)
			if err == nil {
				return printServiceStatus(out, statuses, time.Now())
			}
			if !os.IsNotExist(err) {
				return err
			}
			// No status file: the controller is not running. Show the
			// configured services so the command is still useful.
			fmt.Fprintln(cmd.ErrOrStderr(),
				"controller not running; showing configured services (no live status)")
			cfg, err := loadConfig(flags.configFile)
			if err != nil {
				return err
			}
			services, err := renderServices(cfg, flags.configDir, flags.binDir)
			if err != nil {
				return err
			}
			return printServices(out, services)
		},
	})

	networkCmd := &cobra.Command{
		Use:   "network",
		Short: "Inspect the node's network configuration",
		Args:  cobra.NoArgs,
	}
	networkCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the interface configuration and its live status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			cfg, err := loadConfig(flags.configFile)
			if err != nil {
				return err
			}
			return printNetworkStatus(cmd.OutOrStdout(), networkStatus(cfg.Interfaces.Ethernets))
		},
	})

	cmd.AddCommand(servicesCmd, networkCmd, command.NewVersion(cmd))

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

// run optionally configures the node's interfaces, discovers the services, and
// hands control to the supervisor, which blocks until shutdown. It returns an
// error only for misconfiguration; a clean shutdown exits the process directly
// from the supervisor.
func run(configDir, configFile, binDir, logDir, dataDir, statusFile string,
	shutdownTimeout time.Duration) error {
	// Tag the controller's own diagnostics so they are distinguishable from
	// the "[<service>]"-prefixed service output the supervisor forwards.
	out := &linePrefixWriter{w: os.Stderr, prefix: []byte("[controller] ")}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The generalized configuration is the single source of truth for the
	// node: the interface addressing and the set of SCION services are both
	// derived from it.
	cfg, err := loadConfig(configFile)
	if err != nil {
		return err
	}

	// Set up interfaces before starting services: the router binds its underlay
	// address at startup, so the address must already be on the link. This waits
	// for clab to attach the link veths and is best-effort (see
	// applyNetworkConfig), so it never blocks the node from coming up.
	if eths := cfg.Interfaces.Ethernets; len(eths) > 0 {
		applyNetworkConfig(eths, log)
		log.Info("applied network configuration", "config", configFile)
	}

	// Create the data directory before starting services: SCION services open
	// their SQLite databases there but do not create the parent directory. This
	// is best-effort — a service whose database lives elsewhere still works.
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			log.Warn("cannot create data directory", "dir", dataDir, "err", err)
		}
	}

	// Render the configuration into the per-service TOML files (written
	// into configDir) and derive the services to supervise from them.
	services, err := renderServices(cfg, configDir, binDir)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("no SCION services in configuration %q", configFile)
	}
	for _, svc := range services {
		log.Info("discovered service", "service", svc.name, "binary", svc.binary, "args", svc.args)
	}

	// Per-service log files are best-effort: if the directory can't be created
	// we keep the merged stdout stream rather than failing the whole node.
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			log.Warn("cannot create log directory; per-service files disabled",
				"dir", logDir, "err", err)
			logDir = ""
		}
	}

	// The status file is likewise best-effort: if its directory can't be created
	// the node still runs, only `list services` loses live status.
	if statusFile != "" {
		if err := os.MkdirAll(filepath.Dir(statusFile), 0o755); err != nil {
			log.Warn("cannot create status directory; live status disabled",
				"dir", filepath.Dir(statusFile), "err", err)
			statusFile = ""
		}
	}

	newSupervisor(services, log, shutdownTimeout, logDir, statusFile).run()
	return nil
}

// loadConfig reads and decodes the generalized configuration at path. YAML
// is a superset of JSON, so the YAML decoder handles either serialization that
// testgen emits.
func loadConfig(path string) (config.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("reading config %q: %w", path, err)
	}
	cfg, err := config.DecodeYAML(raw)
	if err != nil {
		return config.Config{}, fmt.Errorf("parsing config %q: %w", path, err)
	}
	return cfg, nil
}

// envOr returns the value of the environment variable key, or def if unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// linePrefixWriter prepends prefix to the start of every line it forwards to w.
// slog's text handler emits one record per Write, but handling embedded
// newlines keeps the tagging correct for multi-line records too.
type linePrefixWriter struct {
	w      io.Writer
	prefix []byte
}

func (lp *linePrefixWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(p)+len(lp.prefix))
	atLineStart := true
	for _, b := range p {
		if atLineStart {
			buf = append(buf, lp.prefix...)
			atLineStart = false
		}
		buf = append(buf, b)
		if b == '\n' {
			atLineStart = true
		}
	}
	if _, err := lp.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}
