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
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/tools/scmp/cmn"
	"github.com/scionproto/scion/go/tools/scmp/echo"
	"github.com/scionproto/scion/go/tools/scmp/recordpath"
	"github.com/scionproto/scion/go/tools/scmp/traceroute"
)

var (
	sciondAddr = flag.String("sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	dispatcher = flag.String("dispatcher", reliable.DefaultDispPath, "Path to dispatcher socket")
	refresh    = flag.Bool("refresh", false, "Set refresh flag for SCIOND path request")
	version    = flag.Bool("version", false, "Output version information and exit.")
	sdConn     sciond.Connector
	localMtu   uint16
)

func main() {
	var err error
	cmd := cmn.ParseFlags(version)
	cmn.ValidateFlags()
	// Connect to sciond
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	sd := sciond.NewService(*sciondAddr)
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
	dispatcherService := reliable.NewDispatcher(*dispatcher)
	cmn.Conn, _, err = dispatcherService.Register(context.Background(), cmn.LocalIA,
		&net.UDPAddr{IP: cmn.LocalIP}, addr.SvcNone)
	if err != nil {
		cmn.Fatal("Unable to register with the dispatcher addr=%s\nerr=%v", cmn.LocalIP, err)
	}
	defer cmn.Conn.Close()

	ret := doCommand(cmd)
	os.Exit(ret)
}

func doCommand(cmd string) int {
	switch cmd {
	case "echo":
		echo.Run()
	case "tr", "traceroute":
		traceroute.Run()
	case "rp", "recordpath":
		recordpath.Run()
	default:
		fmt.Fprintf(os.Stderr, "ERROR: Invalid command %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}

	if cmn.Stats.Sent != cmn.Stats.Recv {
		return 1
	}
	return 0
}

func choosePath() snet.Path {
	paths, err := sdConn.Paths(context.Background(), cmn.Remote.IA, cmn.LocalIA,
		sciond.PathReqFlags{Refresh: *refresh})
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
	cmn.Mtu = path.MTU()
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
