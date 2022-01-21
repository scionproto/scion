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

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/flag"
	"github.com/scionproto/scion/go/pkg/app/path"
	"github.com/scionproto/scion/go/pkg/traceroute"
)

func newTraceroute(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		features    []string
		interactive bool
		logLevel    string
		noColor     bool
		refresh     bool
		sequence    string
		timeout     time.Duration
		tracer      string
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
%s`, app.SequenceHelp),

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := snet.ParseUDPAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing remote", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			closer, err := setupTracer("traceroute", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()

			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()
			dispatcher := envFlags.Dispatcher()
			localIP := envFlags.Local().IPAddr().IP
			log.Debug("Resolved SCION environment flags",
				"daemon", daemonAddr,
				"dispatcher", dispatcher,
				"local", localIP,
			)

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			span.SetTag("dst.isd_as", remote.IA)
			span.SetTag("dst.host", remote.Host.IP)
			defer span.Finish()

			ctx, cancelF := context.WithTimeout(traceCtx, time.Second)
			defer cancelF()
			sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to SCION Daemon", err)
			}
			info, err := app.QueryASInfo(traceCtx, sd)
			if err != nil {
				return err
			}
			span.SetTag("src.isd_as", info.IA)
			path, err := path.Choose(traceCtx, sd, remote.IA,
				path.WithInteractive(flags.interactive),
				path.WithRefresh(flags.refresh),
				path.WithSequence(flags.sequence),
				path.WithColorScheme(path.DefaultColorScheme(flags.noColor)),
			)
			if err != nil {
				return err
			}
			remote.Path = path.Dataplane()
			remote.NextHop = path.UnderlayNextHop()
			if remote.NextHop == nil {
				remote.NextHop = &net.UDPAddr{
					IP:   remote.Host.IP,
					Port: topology.EndhostPort,
				}
			}

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
			span.SetTag("src.host", localIP)
			local := &snet.UDPAddr{
				IA:   info.IA,
				Host: &net.UDPAddr{IP: localIP},
			}
			ctx = app.WithSignal(traceCtx, os.Interrupt, syscall.SIGTERM)
			var stats traceroute.Stats
			cfg := traceroute.Config{
				Dispatcher:   reliable.NewDispatcher(dispatcher),
				Remote:       remote,
				MTU:          path.Metadata().MTU,
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

	envFlags.Register(cmd.Flags())
	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")
	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", time.Second, "timeout per packet")
	cmd.Flags().StringVar(&flags.sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
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
