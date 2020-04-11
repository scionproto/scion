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
	local      net.IP
}

var showpathsCmd = &cobra.Command{
	Use:   "showpaths",
	Short: "A clean-slate internet architecture",
	Args:  cobra.ExactArgs(1),
	Long: `'showpaths' lists available paths between the local and the specified SCION ASe a.

By default, the paths are not probed. As paths might be served from the SCION Deamon's
cache, they might not forward traffic successfully (e.g. if a network link went down).
To list the paths with their health statuses, specify that the paths should be probed
through the flag.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Do not output help message if we get this far.
		cmd.SilenceUsage = true

		dst, err := addr.IAFromString(args[0])
		if err != nil {
			return serrors.WrapStr("invalid destination ISD-AS", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), showpathsFlags.timeout)
		defer cancel()
		opts := []showpaths.Option{
			showpaths.SCIOND(showpathsFlags.sciond),
			showpaths.MaxPaths(showpathsFlags.maxPaths),
			showpaths.ShowExpiration(showpathsFlags.expiration),
			showpaths.Refresh(showpathsFlags.refresh),
			showpaths.Probe(showpathsFlags.probe),
		}
		if showpathsFlags.local != nil {
			opts = append(opts, showpaths.Local(showpathsFlags.local))
		}
		if err := showpaths.Run(ctx, dst, opts...); err != nil {
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
	showpathsCmd.Flags().IPVarP(&showpathsFlags.local, "local", "l", nil,
		"Optional local IP address to use for probing health checks")
}
