// Copyright 2020 Anapaya Systems
// Copyright 2024 OVGU Magdeburg
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

//go:build windows

package launcher

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app/command"
	libconfig "github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

// Windows-specific configuration keys
const (
	cfgLogFile = "logfile"
)

// Event IDs for the system event log used by the launcher
const (
	eventIdStarted = 1
	eventIdStopped = 2
	eventIdFailed  = 3
)

// Application models a SCION server application.
type Application struct {
	// TOMLConfig holds the Go data structure for the application-specific
	// TOML configuration. The Application launcher will check if the TOMLConfig
	// supports additional methods (e.g., custom logging or instance ID) and
	// extract them from the config if that is the case. See the XxxConfig interfaces
	// in this package for more information.
	TOMLConfig libconfig.Config

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

	// cmd is the Cobra command for a SCION server application.
	cmd *cobra.Command

	// config contains the Viper configuration KV store.
	config *viper.Viper

	// isService indicates whether the application was started as a Windows service.
	isService bool

	// elog is the application's Windows event log
	elog debug.Log

	// svcErr is the Go error returned from the service's Execute function.
	svcErr error
}

// Run sets up the common SCION server harness, and then passes control to the Main
// function (if one exists).
//
// Run uses the following globals:
//
//	os.Args
//
// Run will exit the application if it encounters a fatal error.
func (a *Application) Run() {
	if ec, err := a.run(); err != nil {
		fmt.Fprintf(a.getErrorWriter(), "fatal error: %v\n", err)
		os.Exit(ec)
	}
}

func (a *Application) run() (int, error) {
	var err error
	a.isService, err = svc.IsWindowsService()
	if err != nil {
		return 1, err
	}

	executable := filepath.Base(os.Args[0])
	shortName := a.getShortName(executable)

	a.cmd = newCommandTemplate(executable, shortName, a.TOMLConfig, a.Samplers...)
	a.cmd.Flags().String(cfgLogFile, "", "Log file (redirects console output)")
	a.cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return a.executeCommand(cmd.Context(), shortName)
	}
	a.config = viper.New()
	a.config.SetDefault(cfgLogConsoleLevel, log.DefaultConsoleLevel)
	a.config.SetDefault(cfgLogConsoleFormat, "human")
	a.config.SetDefault(cfgLogConsoleStacktraceLevel, log.DefaultStacktraceLevel)
	a.config.SetDefault(cfgGeneralID, executable)
	// The configuration file location is specified through command-line flags.
	// Once the comand-line flags are parsed, we register the location of the
	// config file with the viper config.
	if err := a.config.BindPFlag(cfgConfigFile, a.cmd.Flags().Lookup(cfgConfigFile)); err != nil {
		return 1, err
	}
	if err := a.config.BindPFlag(cfgLogFile, a.cmd.Flags().Lookup(cfgLogFile)); err != nil {
		return 1, err
	}

	if a.isService {
		a.elog, err = eventlog.Open(shortName)
		if err != nil {
			return 1, err
		}
		err = svc.Run(shortName, a)
	} else {
		a.elog = debug.New(shortName)
		err = debug.Run(shortName, a)
	}
	if err != nil {
		ec := err.(syscall.Errno)
		return int(ec), a.svcErr
	}
	return 0, nil
}

// Execute is necessary to implement the srv.Handler interface.
// It controls the lifecycle of a Windows service.
func (a *Application) Execute(
	args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status,
) (appSpecificEc bool, ec uint32) {

	appSpecificEc = true
	ec = 0

	// Accept no controls until initialization has finished
	changes <- svc.Status{State: svc.Running, Accepts: 0}

	// Windows does not support POSIX signals, use a cancellable context to
	// initiate clean shutdown instead.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		defer log.HandlePanic()
		done <- a.cmd.ExecuteContext(ctx)
	}()

	// Service is ready to accept controls
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	a.elog.Info(eventIdStarted, "Service started")
loop:
	for {
		select {
		case a.svcErr = <-done:
			// Main exited on its own
			if a.svcErr != nil {
				ec = 1
				a.elog.Error(eventIdFailed, fmt.Sprintf("%v", a.svcErr))
			}
			cancel()
			return
		case c := <-r:
			// Service control signal
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				break loop
			default:
				msg := fmt.Sprintf("Unexpected service control request %d", c.Cmd)
				a.elog.Error(eventIdFailed, msg)
				panic(msg)
			}
		}
	}

	// If the main goroutine shuts down everything in time, this won't get
	// a chance to run.
	time.AfterFunc(5*time.Second, func() {
		defer log.HandlePanic()
		msg := "Main goroutine did not shut down in time (waited 5s). " +
			"It's probably stuck. Forcing shutdown."
		a.elog.Error(eventIdFailed, msg)
		panic(msg)
	})

	if a.svcErr = <-done; a.svcErr != nil {
		ec = 1
		a.elog.Error(eventIdFailed, fmt.Sprintf("%v", a.svcErr))
	}
	changes <- svc.Status{State: svc.Stopped}
	a.elog.Info(eventIdStopped, "Service stopped")
	return
}

func (a *Application) getShortName(executable string) string {
	if a.ShortName != "" {
		return a.ShortName
	}
	return executable
}

func (a *Application) executeCommand(ctx context.Context, shortName string) error {
	os.Setenv("TZ", "UTC")

	// Load launcher configurations from the same config file as the custom
	// application configuration.
	a.config.SetConfigType("toml")
	a.config.SetConfigFile(a.config.GetString(cfgConfigFile))
	if err := a.config.ReadInConfig(); err != nil {
		return serrors.Wrap("loading generic server config from file", err,
			"file", a.config.GetString(cfgConfigFile))

	}

	if err := libconfig.LoadFile(a.config.GetString(cfgConfigFile), a.TOMLConfig); err != nil {
		return serrors.Wrap("loading config from file", err,
			"file", a.config.GetString(cfgConfigFile))

	}
	a.TOMLConfig.InitDefaults()

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

	if a.config.GetString(cfgLogFile) != "" {
		// Windows services do not have stdout and stderr, redirect to a log file instead.
		file := a.config.GetString(cfgLogFile)
		logfile, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o660)
		if err != nil {
			return fmt.Errorf("cannot open log file: %s", file)
		}
		// We don't close Stdout, Stderr or logfile in case anyone still holds a reference.
		os.Stdout = logfile
		os.Stderr = logfile
	}

	if err := log.Setup(a.getLogging(), opt); err != nil {
		return serrors.Wrap("initialize logging", err)
	}
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

func (a *Application) getLogging() log.Config {
	return log.Config{
		Console: log.ConsoleConfig{
			Level:           a.config.GetString(cfgLogConsoleLevel),
			Format:          a.config.GetString(cfgLogConsoleFormat),
			StacktraceLevel: a.config.GetString(cfgLogConsoleStacktraceLevel),
		},
	}
}

func (a *Application) getErrorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}
