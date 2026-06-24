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

// Controller is the PID 1 init and process supervisor for a SCION
// containerlab node (one ISD-AS per node). It discovers the SCION service
// configurations bind-mounted into the node, launches the dispatcher, router,
// control, and daemon processes, reaps children, and shuts them down cleanly.
//
// There is no configuration API yet: the set of services is derived entirely
// from the TOML files present in the config directory at start time.
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
)

func main() {
	executable := filepath.Base(os.Args[0])

	var flags struct {
		configDir       string
		binDir          string
		logDir          string
		shutdownTimeout time.Duration
	}

	cmd := &cobra.Command{
		Use:   executable,
		Short: "SCION containerlab node controller",
		Long: executable + ` is the PID 1 init and process supervisor for a SCION
containerlab node (one ISD-AS per node).

It discovers the per-service SCION configuration bind-mounted into the node,
launches the dispatcher, router, control, and daemon processes, reaps children
(including reparented orphans), restarts crashed services with backoff, and
shuts everything down cleanly on SIGTERM/SIGINT.

The set of services is derived entirely from the TOML files present in the
configuration directory at start time; there is no configuration API yet.`,
		Args: cobra.NoArgs,
		// Errors and usage are handled in main; don't let cobra print usage on
		// a runtime error from RunE.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags.configDir, flags.binDir, flags.logDir, flags.shutdownTimeout)
		},
	}

	cmd.Flags().StringVar(&flags.configDir, "config-dir", envOr("SCION_CONFIG_DIR", "/etc/scion"),
		"directory holding the bind-mounted SCION service configuration")
	cmd.Flags().StringVar(&flags.binDir, "bin-dir", envOr("SCION_BIN_DIR", "/app"),
		"directory holding the SCION service binaries")
	cmd.Flags().StringVar(&flags.logDir, "log-dir", envOr("SCION_LOG_DIR", "/var/log/scion"),
		"directory for per-service log files; empty disables them (output still goes to stdout)")
	cmd.Flags().DurationVar(&flags.shutdownTimeout, "shutdown-timeout", 10*time.Second,
		"grace period for services to stop on shutdown before SIGKILL")

	cmd.AddCommand(command.NewVersion(cmd))

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

// run discovers the services and hands control to the supervisor, which blocks
// until shutdown. It returns an error only for misconfiguration; a clean
// shutdown exits the process directly from the supervisor.
func run(configDir, binDir, logDir string, shutdownTimeout time.Duration) error {
	// Tag the controller's own diagnostics so they are distinguishable from
	// the "[<service>]"-prefixed service output the supervisor forwards.
	out := &linePrefixWriter{w: os.Stderr, prefix: []byte("[controller] ")}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	services, err := discover(configDir, binDir)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("no SCION service configuration found in %q", configDir)
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

	newSupervisor(services, log, shutdownTimeout, logDir).run()
	return nil
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
