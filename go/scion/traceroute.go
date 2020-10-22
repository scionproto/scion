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
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/traceroute"
)

func newTraceroute(pather CommandPather) *cobra.Command {
	var flags struct {
		dispatcher  string
		features    []string
		interactive bool
		local       net.IP
		noColor     bool
		refresh     bool
		sciond      string
		sequence    string
		timeout     time.Duration
	}

	var cmd = &cobra.Command{
		Use:     "traceroute [flags] <remote>",
		Aliases: []string{"tr"},
		Short:   "Trace the SCION route to a remote SCION AS using SCMP traceroute packets",
		Example: fmt.Sprintf("  %[1]s traceroute 1-ff00:0:110,10.0.0.1", pather.CommandPath()),
		Long: fmt.Sprintf(`'traceroute' traces the SCION path to a remote AS using
SCMP traceroute packets.

If any packet is dropped, traceroute will exit with code 1.
On other errors, traceroute will exit with code 2.
%s`, filterHelp),

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			remote, err := snet.ParseUDPAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing remote", err)
			}
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()
			sd, err := sciond.NewService(flags.sciond).Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to SCION Daemon", err)
			}
			info, err := app.QueryASInfo(context.Background(), sd)
			if err != nil {
				return err
			}
			path, err := app.ChoosePath(context.Background(), sd, remote.IA,
				flags.interactive, flags.refresh, flags.sequence,
				app.WithDisableColor(flags.noColor))
			if err != nil {
				return err
			}
			remote.Path = path.Path()
			remote.NextHop = path.UnderlayNextHop()
			if remote.NextHop == nil {
				remote.NextHop = &net.UDPAddr{
					IP:   remote.Host.IP,
					Port: topology.EndhostPort,
				}
			}

			localIP := flags.local
			if localIP == nil {
				target := remote.Host.IP
				if remote.NextHop != nil {
					target = remote.NextHop.IP
				}
				if localIP, err = addrutil.ResolveLocal(target); err != nil {
					return serrors.WrapStr("resolving local address", err)
				}
				fmt.Printf("Resolved local address:\n  %s\n", localIP)
			}
			fmt.Printf("Using path:\n  %s\n\n", path)
			local := &snet.UDPAddr{
				IA:   info.IA,
				Host: &net.UDPAddr{IP: localIP},
			}
			ctx = app.WithSignal(context.Background(), os.Interrupt, syscall.SIGTERM)
			var stats traceroute.Stats
			cfg := traceroute.Config{
				Dispatcher:   reliable.NewDispatcher(flags.dispatcher),
				Remote:       remote,
				MTU:          path.Metadata().MTU(),
				Local:        local,
				PathEntry:    path,
				Timeout:      flags.timeout,
				ProbesPerHop: 3,
				ErrHandler:   func(err error) { fmt.Fprintf(os.Stderr, "ERROR: %s\n", err) },
				UpdateHandler: func(u traceroute.Update) {
					fmt.Printf("%d %s %s\n", u.Index, fmtRemote(u.Remote, u.Interface),
						fmtRTTs(u.RTTs, flags.timeout))
				},
			}
			stats, err = traceroute.Run(ctx, cfg)
			if err != nil {
				return err
			}
			if stats.Sent != stats.Recv {
				return app.WithExitCode(serrors.New("packets were lost"), 1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")
	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", time.Second, "timeout per packet")
	cmd.Flags().IPVar(&flags.local, "local", nil, "IP address to listen on")
	cmd.Flags().StringVar(&flags.dispatcher, "dispatcher", reliable.DefaultDispPath,
		"dispatcher socket")
	cmd.Flags().StringVar(&flags.sciond, "sciond", sciond.DefaultAPIAddress, "SCION Daemon address")
	cmd.Flags().StringVar(&flags.sequence, "sequence", "", "sequence space separated list of HPs")
	return cmd
}

func fmtRTTs(rtts []time.Duration, timeout time.Duration) string {
	parts := make([]string, 0, len(rtts))
	for _, rtt := range rtts {
		if rtt > timeout {
			parts = append(parts, "*")
			continue
		}
		parts = append(parts, rtt.String())
	}
	return strings.Join(parts, " ")
}

func fmtRemote(remote *snet.UDPAddr, intf uint64) string {
	if remote == nil {
		return "??"
	}
	return fmt.Sprintf("%s IfID=%d", remote, intf)
}
