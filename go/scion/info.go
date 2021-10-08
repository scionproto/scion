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

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/pkg/app"
)

func newInfo(pather CommandPather) *cobra.Command {
	var flags struct {
		daemon string
	}

	var cmd = &cobra.Command{
		Use:     "info [flags]",
		Short:   "Show relevant, locally-known info about this SCION host, such as its SCION address",
		Example: fmt.Sprintf(`  %[1]s info`, pather.CommandPath()),
		Long: `'info' show info about this SCION host

This functionality is intended to work similarly to 'ip addr' or 'ifconfig' and return relevant, locally-known info about this host's relationship with SCION.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			ctx := context.Background()
			sd, err := daemon.NewService(flags.daemon).Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to SCION Daemon", err)
			}

			//info, err := app.QueryASInfo(traceCtx, sd)
			info, err := app.QueryASInfo(ctx, sd)
			if err != nil {
				return err
			}

			localIP, err := addrutil.DefaultLocalIP(ctx, sd)
			if err != nil {
				return err
			}

			fmt.Printf("One of this host's SCION addresses is:\n\n    %s,%s\n\n", info.IA, localIP)
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.daemon, "sciond", daemon.DefaultAPIAddress, "SCION Daemon address")
	return cmd
}
