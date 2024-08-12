// Copyright 2021 Thorben Krüger <thorben.krueger@ovgu.de>
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
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
)

type addrInfo struct {
	IA      addr.IA `json:"isd_as"`
	IP      net.IP  `json:"ip"`
	Address string  `json:"address"`
}

func newAddress(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		json bool
	}

	var cmd = &cobra.Command{
		Use:     "address [flags]",
		Short:   "Show (one of) this host's SCION address(es)",
		Example: fmt.Sprintf(`  %[1]s address`, pather.CommandPath()),
		Long: `'address' show address information about this SCION host.

This command returns the relevant SCION address information for this host.

Currently, this returns a sensible but arbitrary local address. In the general
case, the host could have multiple SCION addresses.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()

			cmd.SilenceUsage = true
			ctx, cancelF := context.WithTimeout(cmd.Context(), time.Second)
			defer cancelF()
			sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			if err != nil {
				return serrors.Wrap("connecting to SCION Daemon", err)
			}
			defer sd.Close()

			info, err := app.QueryASInfo(ctx, sd)
			if err != nil {
				return err
			}

			localIP, err := addrutil.DefaultLocalIP(ctx, sd)
			if err != nil {
				return err
			}
			address := fmt.Sprintf("%s,%s", info.IA, localIP)
			if !flags.json {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), address)
				return err
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string][]addrInfo{
				"addresses": {{
					IA:      info.IA,
					IP:      localIP,
					Address: address,
				}},
			})
		},
	}
	envFlags.Register(cmd.Flags())
	cmd.Flags().BoolVar(&flags.json, "json", false, "Write the output as machine readable json")

	return cmd
}
