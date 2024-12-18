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
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/scionproto/scion/pkg/log"
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
	ApplicationBase

	// cmd is the Cobra command for a SCION server application.
	cmd *cobra.Command

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

func (a *Application) executeCommand(ctx context.Context, shortName string) error {

	if err := a.ApplicationBase.loadConfig(); err != nil {
		return err
	}
	if err := a.ApplicationBase.initLogging(); err != nil {
		return err
	}

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

	return a.ApplicationBase.executeCommand(ctx, shortName)
}
