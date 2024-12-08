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

//go:build !windows

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

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/app"
)

// Application models a SCION server application.
type Application struct {
	ApplicationBase
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
	if err := a.run(); err != nil {
		fmt.Fprintf(a.getErrorWriter(), "fatal error: %v\n", err)
		os.Exit(1)
	}
}

func (a *Application) run() error {
	executable := filepath.Base(os.Args[0])
	shortName := a.getShortName(executable)

	cmd := newCommandTemplate(executable, shortName, a.TOMLConfig, a.Samplers...)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
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
	if err := a.config.BindPFlag(cfgConfigFile, cmd.Flags().Lookup(cfgConfigFile)); err != nil {
		return err
	}

	// All servers accept SIGTERM to perform clean shutdown (for example, this
	// is used behind the scenes by docker stop to cleanly shut down a container).
	sigtermCtx := app.WithSignal(context.Background(), syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer log.HandlePanic()
		<-sigtermCtx.Done()
		log.Info("Received SIGTERM signal, exiting...")

		// If the main goroutine shuts down everything in time, this won't get
		// a chance to run.
		time.AfterFunc(5*time.Second, func() {
			defer log.HandlePanic()
			panic("Main goroutine did not shut down in time (waited 5s). " +
				"It's probably stuck. Forcing shutdown.")
		})

		cancel()
	}()

	return cmd.ExecuteContext(ctx)
}

func (a *Application) executeCommand(ctx context.Context, shortName string) error {

	if err := a.ApplicationBase.loadConfig(); err != nil {
		return err
	}
	if err := a.ApplicationBase.initLogging(); err != nil {
		return err
	}

	return a.ApplicationBase.executeCommand(ctx, shortName)
}
