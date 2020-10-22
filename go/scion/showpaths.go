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

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/showpaths"
)

func newShowpaths(pather CommandPather) *cobra.Command {
	var flags struct {
		timeout    time.Duration
		cfg        showpaths.Config
		expiration bool
		json       bool
		noColor    bool
	}

	var cmd = &cobra.Command{
		Use:     "showpaths",
		Short:   "Display paths to a SCION AS",
		Aliases: []string{"sp"},
		Args:    cobra.ExactArgs(1),
		Example: fmt.Sprintf(`  %[1]s showpaths 1-ff00:0:110 --expiration
  %[1]s showpaths 1-ff00:0:110 --local 127.0.0.55 --json
  %[1]s showpaths 1-ff00:0:111 --sequence="0-0#2 0*" # outgoing IfID=2
  %[1]s showpaths 1-ff00:0:111 --sequence="0* 0-0#41" # incoming IfID=41 at dstIA
  %[1]s showpaths 1-ff00:0:111 --sequence="0* 1-ff00:0:112 0*" # 1-ff00:0:112 on the path
  %[1]s showpaths 1-ff00:0:110 --no-probe`, pather.CommandPath()),
		Long: fmt.Sprintf(`'showpaths' lists available paths between the local and the specified
SCION ASe a.

By default, the paths are probed. Paths served from the SCION Deamon's might not
forward traffic successfully (e.g. if a network link went down, or there is a black
hole on the path). To disable path probing, set the appropriate flag.

'showpaths' can be instructed to output the paths as json using the the --json flag.

If no alive path is discovered, json output is not enabled, and probing is not
disabled, showpaths will exit with the code 1.
On other errors, showpaths will exit with code 2.

%s`, filterHelp),
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, err := addr.IAFromString(args[0])
			if err != nil {
				return serrors.WrapStr("invalid destination ISD-AS", err)
			}

			// At this point it is reasonable to assume that the caller knows how to
			// call the command. Silence the usage help output on error, because subsequent
			// errors are likely not caused malformed CLI arguments.
			// See https://github.com/spf13/cobra/issues/340
			cmd.SilenceUsage = true

			// FIXME(roosd): This practically turns of logging done in libraries. We
			// should not have to do this.
			log.Setup(log.Config{Console: log.ConsoleConfig{Level: "crit"}})

			ctx, cancel := context.WithTimeout(context.Background(), flags.timeout)
			defer cancel()
			res, err := showpaths.Run(ctx, dst, flags.cfg)
			if err != nil {
				return err
			}
			if flags.json {
				return res.JSON(os.Stdout)
			}
			fmt.Fprintln(os.Stdout, "Available paths to", res.Destination)
			if len(res.Paths) == 0 {
				return app.WithExitCode(serrors.New("no path found"), 1)
			}
			res.Human(os.Stdout, flags.expiration, !flags.noColor)
			if res.Alive() == 0 && !flags.cfg.NoProbe {
				return app.WithExitCode(serrors.New("no path alive"), 1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.cfg.SCIOND, "sciond",
		sciond.DefaultAPIAddress, "SCION Deamon address")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Timeout")
	cmd.Flags().StringVar(&flags.cfg.Sequence, "sequence",
		"", "sequence space separated list of HPs")
	cmd.Flags().IntVarP(&flags.cfg.MaxPaths, "maxpaths", "m", 10,
		"Maximum number of paths that are displayed")
	cmd.Flags().BoolVarP(&flags.expiration, "expiration", "e", false,
		"Show path expiration information")
	cmd.Flags().BoolVarP(&flags.cfg.Refresh, "refresh", "r", false,
		"Set refresh flag for SCION Deamon path request")
	cmd.Flags().BoolVar(&flags.cfg.NoProbe, "no-probe", false,
		"Do not probe the paths and print the health status")
	cmd.Flags().BoolVarP(&flags.json, "json", "j", false,
		"Write the output as machine readable json")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().IPVarP(&flags.cfg.Local, "local", "l", nil,
		"Optional local IP address to use for probing health checks")

	return cmd
}
