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
	"math"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/ping"
)

func newPing(pather CommandPather) *cobra.Command {
	var flags struct {
		count       uint16
		interval    time.Duration
		size        uint
		interactive bool
		local       net.IP
		refresh     bool
		sciond      string
		dispatcher  string
		timeout     time.Duration
		maxMTU      bool
		noColor     bool

		features []string
	}

	var cmd = &cobra.Command{
		Use:     "ping [flags] <remote>",
		Short:   "Test connectivity to a remote SCION host using SCMP echo packets",
		Example: fmt.Sprintf("  %[1]s ping 1-ff00:0:110,10.0.0.1", pather.CommandPath()),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := snet.ParseUDPAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing remote", err)
			}
			cmd.SilenceUsage = true

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
				flags.interactive, flags.refresh, app.WithDisableColor(flags.noColor))
			if err != nil {
				return err
			}
			remote.Path = path.Path()
			remote.NextHop = path.UnderlayNextHop()

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
			pldSize := int(flags.size)
			if flags.maxMTU {
				mtu := int(path.Metadata().MTU())
				pldSize, err = calcMaxPldSize(local, remote, mtu)
				if err != nil {
					return err
				}
			}
			pktSize, err := ping.Size(local, remote, pldSize)
			if err != nil {
				return err
			}
			fmt.Printf("PING %s pld=%dB scion_pkt=%dB\n", remote, pldSize, pktSize)

			start := time.Now()
			ctx = app.WithSignal(context.Background(), os.Interrupt, syscall.SIGTERM)
			count := flags.count
			if count == 0 {
				count = math.MaxUint16
			}
			stats, err := ping.Run(ctx, ping.Config{
				Dispatcher:  reliable.NewDispatcher(flags.dispatcher),
				Attempts:    count,
				Interval:    flags.interval,
				Timeout:     flags.timeout,
				Local:       local,
				Remote:      remote,
				PayloadSize: int(flags.size),
				ErrHandler: func(err error) {
					fmt.Fprintf(os.Stderr, "ERROR: %s", err)
				},
				UpdateHandler: func(update ping.Update) {
					var additional string
					switch update.State {
					case ping.AfterTimeout:
						additional = " state=After timeout"
					case ping.OutOfOrder:
						additional = " state=Out of Order"
					case ping.Duplicate:
						additional = " state=Duplicate"
					}
					fmt.Fprintf(os.Stdout, "%d bytes from %s,%s: scmp_seq=%d time=%s%s\n",
						update.Size, update.Source.IA, update.Source.Host, update.Sequence,
						update.RTT, additional)
				},
			})
			pingSummary(stats, remote, time.Since(start))
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no_color", false, "disable colored output")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", time.Second, "timeout per packet")
	cmd.Flags().IPVar(&flags.local, "local", nil, "IP address to listen on")
	cmd.Flags().StringVar(&flags.sciond, "sciond", sciond.DefaultAPIAddress, "SCION Daemon address")
	cmd.Flags().StringVar(&flags.dispatcher, "dispatcher", reliable.DefaultDispPath,
		"dispatcher socket")
	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")
	cmd.Flags().DurationVar(&flags.interval, "interval", time.Second, "time between packets")
	cmd.Flags().Uint16VarP(&flags.count, "count", "c", 0, "total number of packets to send")
	cmd.Flags().UintVarP(&flags.size, "payload_size", "s", 0,
		`number of bytes to be sent in addition to the SCION Header and SCMP echo header;
the total size of the packet is still variable size due to the variable size of
the SCION path.`,
	)
	cmd.Flags().BoolVar(&flags.maxMTU, "max_mtu", false,
		`choose the payload size such that the sent SCION packet including the SCION Header,
SCMP echo header and payload are equal to the MTU of the path. This flag overrides the
'payload_size' flag.`)
	return cmd
}

func calcMaxPldSize(local, remote *snet.UDPAddr, mtu int) (int, error) {
	overhead, err := ping.Size(local, remote, 0)
	if err != nil {
		return 0, err
	}
	return mtu - overhead, nil
}

func pingSummary(stats ping.Stats, remote *snet.UDPAddr, run time.Duration) {
	var pktLoss int
	if stats.Sent != 0 {
		pktLoss = 100 - stats.Received*100/stats.Sent
	}
	fmt.Printf("\n--- %s,%s statistics ---\n", remote.IA, remote.Host.IP)
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
		stats.Sent, stats.Received, pktLoss, run.Round(time.Microsecond))
}
