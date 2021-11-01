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
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/flag"
)

func newAddress(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		json bool
	}

	var cmd = &cobra.Command{
		Use:     "address [flags]",
		Short:   "Show (one of) this host's SCION address(es)",
		Example: fmt.Sprintf(`  %[1]s address`, pather.CommandPath()),
		Long: `'address' show address information about this SCION host

This functionality is intended to work similarly to 'ip addr' or 'ifconfig' and 
return relevant, locally-known SCION address information for this host`,
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
				return serrors.WrapStr("connecting to SCION Daemon", err)
			}

			info, err := app.QueryASInfo(ctx, sd)
			if err != nil {
				return err
			}

			localIP, err := addrutil.DefaultLocalIP(ctx, sd)
			if err != nil {
				return err
			}
			if !flags.json {
				fmt.Printf("%s,%s\n", info.IA, localIP)
			} else {
				fmt.Printf(`{
  "addresses": [
    {
      "isd_as": "%s",
      "ip": "%s",
      "address": "%s,%s"
    }
  ]
}`, info.IA, localIP, info.IA, localIP)
			}

			return nil
		},
	}
	envFlags.Register(cmd.Flags())
	cmd.Flags().BoolVar(&flags.json, "json", false, "output address info in machine-readable form")

	return cmd
}
