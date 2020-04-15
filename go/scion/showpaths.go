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
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/showpaths"
)

var showpathsFlags struct {
	sciond     string
	timeout    time.Duration
	maxPaths   int
	expiration bool
	refresh    bool
	probe      bool
	json       bool
	local      net.IP
}

var showpathsCmd = &cobra.Command{
	Use:   "showpaths",
	Short: "Display paths to a SCION AS",
	Args:  cobra.ExactArgs(1),
	Example: `  scion showpaths 1-ff00:0:110 --probe --expiration
  scion showpaths 1-ff00:0:110 --probe --json
  scion showpaths 1-ff00:0:110 --local 127.0.0.55`,
	Long: `'showpaths' lists available paths between the local and the specified SCION ASe a.

By default, the paths are not probed. As paths might be served from the SCION Deamon's
cache, they might not forward traffic successfully (e.g. if a network link went down).
To list the paths with their health statuses, specify that the paths should be probed
through the flag.

'showpaths' can be instructed to output the paths as json using the the --json flag.
`,
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

		ctx, cancel := context.WithTimeout(context.Background(), showpathsFlags.timeout)
		defer cancel()
		cfg := showpaths.Config{
			Local:          showpathsFlags.local,
			SCIOND:         showpathsFlags.sciond,
			MaxPaths:       showpathsFlags.maxPaths,
			ShowExpiration: showpathsFlags.expiration,
			Refresh:        showpathsFlags.refresh,
			Probe:          showpathsFlags.probe,
			JSON:           showpathsFlags.json,
		}
		if err := showpaths.Run(ctx, dst, cfg); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(showpathsCmd)
	showpathsCmd.Flags().StringVar(&showpathsFlags.sciond, "sciond", sciond.DefaultSCIONDAddress,
		"SCION Deamon address")
	showpathsCmd.Flags().DurationVar(&showpathsFlags.timeout, "timeout", 5*time.Second, "Timeout")
	showpathsCmd.Flags().IntVarP(&showpathsFlags.maxPaths, "maxpaths", "m", 10,
		"Maximum number of paths that are displayed")
	showpathsCmd.Flags().BoolVarP(&showpathsFlags.expiration, "expiration", "e", false,
		"Show path expiration information")
	showpathsCmd.Flags().BoolVarP(&showpathsFlags.refresh, "refresh", "r", false,
		"Set refresh flag for SCION Deamon path request")
	showpathsCmd.Flags().BoolVarP(&showpathsFlags.probe, "probe", "p", false,
		"Probe the paths and print the health status")
	showpathsCmd.Flags().BoolVarP(&showpathsFlags.probe, "json", "j", false,
		"Write the output as machine readable json")
	showpathsCmd.Flags().IPVarP(&showpathsFlags.local, "local", "l", nil,
		"Optional local IP address to use for probing health checks")
}
