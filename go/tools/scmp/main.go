// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Simple echo application for SCION connectivity tests.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/tools/scmp/cmn"
	"github.com/scionproto/scion/go/tools/scmp/echo"
	"github.com/scionproto/scion/go/tools/scmp/recordpath"
	"github.com/scionproto/scion/go/tools/scmp/traceroute"
)

func init() {
	RootCmd.PersistentFlags().BoolVarP(&cmn.Interactive, "interactive", "i", false,
		"interactive mode")
	RootCmd.PersistentFlags().DurationVar(&cmn.Timeout, "timeout", cmn.DefaultTimeout,
		"timeout per packet")
	RootCmd.PersistentFlags().StringVar(&cmn.LocalIPString, "local", "", "IP address to listen on")
	RootCmd.PersistentFlags().StringVar(&sciondAddr, "sciond", sciond.DefaultSCIONDAddress,
		"SCIOND address")
	RootCmd.PersistentFlags().StringVar(&dispatcher, "dispatcher", reliable.DefaultDispPath,
		"path to dispatcher socket")
	RootCmd.PersistentFlags().BoolVar(&refresh, "refresh", false,
		"set refresh flag for SCIOND path request")
	RootCmd.PersistentFlags().BoolVar(&version, "version", false,
		"output version information and exit")

	EchoCmd.Flags().DurationVar(&cmn.Interval, "interval", cmn.DefaultInterval,
		"time between packets")
	EchoCmd.Flags().Uint16VarP(&cmn.Count, "count", "c", 0,
		"total number of packets to send")
	EchoCmd.Flags().UintVarP(&cmn.PayloadSize, "payload_size", "s", 0,
		`number of bytes to be sent in addition to the SCION Header and SCMP echo header;
the total size of the packet is still variable size due to the variable size of
the SCION path.`,
	)

	RootCmd.AddCommand(
		EchoCmd,
		TracerouteCmd,
		RecordpathCmd,
	)

	cmn.Stats = &cmn.ScmpStats{}
	cmn.Start = time.Now()
}

var (
	sciondAddr string
	dispatcher string
	refresh    bool
	version    bool
	sdConn     sciond.Connector
	localMtu   uint16
)

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

var (
	RootCmd = &cobra.Command{
		Use:   "scmp",
		Short: "SCION Control Message Protocol network tool",
		Long: "scmp is a tool for testing SCION networks. It is similar " +
			"to the ping and traceroute utilities of IP networks.",
		PersistentPostRunE: Cleanup,
		SilenceErrors:      true,
		Example:            "  scmp echo 1-ff00:0:1,[10.0.0.1]",
	}

	EchoCmd = &cobra.Command{
		Use:   "echo [flags] <remote>",
		Short: "Test connectivity to a remote SCION host using SCMP echo packets",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.SilenceUsage = true
			Base(args[0])
			echo.Run()
		},
		Example: "  scmp echo 1-ff00:0:1,[10.0.0.1]",
	}

	TracerouteCmd = &cobra.Command{
		Use:     "traceroute [flags] <remote>",
		Aliases: []string{"tr"},
		Short:   "Trace the SCION route to a remote SCION AS using SCMP traceroute packets",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.SilenceUsage = true
			Base(args[0])
			traceroute.Run()
		},
		Example: "  scmp traceroute 1-ff00:0:1,[10.0.0.1]",
	}

	RecordpathCmd = &cobra.Command{
		Use:     "recordpath [flags] <remote>",
		Aliases: []string{"rp"},
		Short:   "Record the SCION path to a remote SCION AS using SCMP recordpath packets",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.SilenceUsage = true
			Base(args[0])
			recordpath.Run()
		},
		Example: "  scmp recordpath 1-ff00:0:1,[10.0.0.1]",
	}
)

func Base(remote string) {
	var err error
	cmn.ValidateFlags()

	if err := cmn.Remote.Set(remote); err != nil {
		cmn.Fatal("Failed to parse remote %v, error: %v\n", err)
	}

	// Connect to sciond
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	sd := sciond.NewService(sciondAddr)
	sdConn, err = sd.Connect(ctx)
	if err != nil {
		cmn.Fatal("Failed to connect to SCIOND: %v\n", err)
	}

	setLocalASInfo()

	// If remote is not in local AS, we need a path!
	var pathStr string
	if !cmn.Remote.IA.Equal(cmn.LocalIA) {
		setPathAndMtu()
		pathStr = fmt.Sprintf("%s", cmn.PathEntry)
		if cmn.LocalIP == nil {
			cmn.LocalIP = resolveLocalIP(cmn.Remote.NextHop.IP)
		}
	} else {
		cmn.Mtu = localMtu
		if cmn.LocalIP == nil {
			cmn.LocalIP = resolveLocalIP(cmn.Remote.Host.IP)
		}
	}
	fmt.Printf("Using path:\n  %s\n", pathStr)

	// Connect to the dispatcher
	dispatcherService := reliable.NewDispatcher(dispatcher)
	cmn.Conn, _, err = dispatcherService.Register(context.Background(), cmn.LocalIA,
		&net.UDPAddr{IP: cmn.LocalIP}, addr.SvcNone)
	if err != nil {
		cmn.Fatal("Unable to register with the dispatcher addr=%s\nerr=%v", cmn.LocalIP, err)
	}
}

func Cleanup(cmd *cobra.Command, _ []string) error {
	if cmn.Stats.Sent != cmn.Stats.Recv {
		return serrors.New("packets were lost")
	}
	if cmn.Conn != nil {
		return cmn.Conn.Close()
	}
	return nil
}

func choosePath() snet.Path {
	paths, err := sdConn.Paths(context.Background(), cmn.Remote.IA, cmn.LocalIA,
		sciond.PathReqFlags{Refresh: refresh})
	if err != nil {
		cmn.Fatal("Failed to retrieve paths from SCIOND: %v\n", err)
	}
	var pathIndex uint64
	if len(paths) == 0 {
		cmn.Fatal("No paths available to remote destination")
	}
	if cmn.Interactive {
		fmt.Printf("Available paths to %v\n", cmn.Remote.IA)
		for i := range paths {
			fmt.Printf("[%2d] %s\n", i, fmt.Sprintf("%s", paths[i]))
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("Choose path: ")
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIndex, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && int(pathIndex) < len(paths) {
				break
			}
			fmt.Fprintf(os.Stderr, "ERROR: Invalid path index, valid indices range: [0, %v]\n",
				len(paths))
		}
	}
	return paths[pathIndex]
}

func setPathAndMtu() {
	path := choosePath()
	cmn.PathEntry = path
	cmn.Remote.Path = path.Path()
	cmn.Remote.NextHop = path.UnderlayNextHop()
	cmn.Mtu = path.Metadata().MTU()
}

// setLocalASInfo queries the local AS information from SCIOND; sets cmn.LocalIA and localMtu.
func setLocalASInfo() {
	asInfo, err := sdConn.ASInfo(context.Background(), addr.IA{})
	if err != nil {
		cmn.Fatal("Failed to query local IA from SCIOND: %v\n", err)
	}
	e0 := asInfo.Entries[0]
	cmn.LocalIA = e0.RawIsdas.IA()
	localMtu = e0.Mtu
}

// resolveLocalIP returns the src IP used for traffic destined to dst
func resolveLocalIP(dst net.IP) net.IP {
	srcIP, err := addrutil.ResolveLocal(dst)
	if err != nil {
		cmn.Fatal("Failed to determine local IP: %v\n", err)
	}
	return srcIP
}
