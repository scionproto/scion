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

// Command testgen turns a small declarative .topo file into a directory tree
// that can run a SCION test topology.
package main

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/testing/clab/testgen"
)

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func cmd() *cobra.Command {
	var flags struct {
		topo       string
		out        string
		networkV4  string
		networkV6  string
		asValidity string
		isdDir     bool
		labName    string
	}

	c := &cobra.Command{
		Use:   "testgen",
		Short: "Generate a SCION test topology from a .topo file",
		Long: `testgen turns a small declarative .topo file into a directory tree that can
run a SCION test topology.

It runs an ordered pipeline: parse, hydrate (allocate subnets and addresses),
config (generalized per-host configuration), service-config (router, control and
daemon files), crypto (TRCs and certificates), clab and instructions. The clab
and instructions phases are not yet implemented.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		Example:       "  testgen -c topology/default.topo -o gen",
		RunE: func(c *cobra.Command, _ []string) error {
			c.SilenceUsage = true

			networkV4, err := netip.ParsePrefix(flags.networkV4)
			if err != nil {
				return fmt.Errorf("parsing --network: %w", err)
			}
			networkV6, err := netip.ParsePrefix(flags.networkV6)
			if err != nil {
				return fmt.Errorf("parsing --network-v6: %w", err)
			}
			validity, err := util.ParseDuration(flags.asValidity)
			if err != nil {
				return fmt.Errorf("parsing --as-validity: %w", err)
			}
			return testgen.Run(testgen.Config{
				TopoFile:   flags.topo,
				OutDir:     flags.out,
				NetworkV4:  networkV4,
				NetworkV6:  networkV6,
				ASValidity: validity,
				ISDDir:     flags.isdDir,
				LabName:    flags.labName,
				Writer:     c.OutOrStdout(),
			})
		},
	}

	def := testgen.DefaultConfig()
	c.Flags().StringVarP(&flags.topo, "topo", "c", "topology/default.topo",
		"Topology description file")
	c.Flags().StringVarP(&flags.out, "out", "o", "gen", "Output directory")
	c.Flags().StringVar(&flags.networkV4, "network", def.NetworkV4.String(),
		"Base IPv4 network for the default allocator")
	c.Flags().StringVar(&flags.networkV6, "network-v6", def.NetworkV6.String(),
		"Base IPv6 network for the default allocator")
	c.Flags().StringVar(&flags.asValidity, "as-validity", "1y", "AS certificate validity")
	c.Flags().BoolVar(&flags.isdDir, "isd-dir", false, "Group ASes in per-ISD directories")
	c.Flags().StringVar(&flags.labName, "name", "scion", "containerlab lab name")
	c.MarkFlagRequired("topo")

	return c
}
