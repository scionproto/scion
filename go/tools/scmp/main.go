// Copyright 2018 ETH Zurich
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
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"

	"github.com/scionproto/scion/go/tools/scmp/cmn"
	"github.com/scionproto/scion/go/tools/scmp/echo"
	"github.com/scionproto/scion/go/tools/scmp/recordpath"
	"github.com/scionproto/scion/go/tools/scmp/traceroute"
)

var (
	sciondPath   = flag.String("sciond", "", "Path to sciond socket")
	dispatcher   = flag.String("dispatcher", "", "Path to dispatcher socket")
	sciondFromIA = flag.Bool("sciondFromIA", false, "SCIOND socket path from IA address:ISD-AS")
)

func main() {
	var err error
	cmd := cmn.ParseFlags()
	cmn.ValidateFlags()
	if *sciondFromIA {
		if *sciondPath != "" {
			cmn.Fatal("Only one of -sciond or -sciondFromIA can be specified")
		}
		if cmn.Local.IA.IsZero() {
			cmn.Fatal("-local flag is missing")
		}
		*sciondPath = sciond.GetDefaultSCIONDPath(&cmn.Local.IA)
	} else if *sciondPath == "" {
		*sciondPath = sciond.GetDefaultSCIONDPath(nil)
	}
	// Initialize default SCION networking context
	if err := snet.Init(cmn.Local.IA, *sciondPath, *dispatcher); err != nil {
		cmn.Fatal("Unable to initialize SCION network\nerr=%v", err)
	}
	// Connect directly to the dispatcher
	address := &reliable.AppAddr{Addr: cmn.Local.Host}
	var bindAddress *reliable.AppAddr
	if cmn.Bind.Host != nil {
		bindAddress = &reliable.AppAddr{Addr: cmn.Bind.Host}
	}
	cmn.Conn, _, err = reliable.Register(*dispatcher, cmn.Local.IA, address,
		bindAddress, addr.SvcNone)
	if err != nil {
		cmn.Fatal("Unable to register with the dispatcher addr=%s\nerr=%v", cmn.Local, err)
	}
	defer cmn.Conn.Close()

	// If remote is not in local AS, we need a path!
	var pathStr string
	if !cmn.Remote.IA.Eq(cmn.Local.IA) {
		cmn.Mtu = setPathAndMtu()
		pathStr = cmn.PathEntry.Path.String()
	} else {
		cmn.Mtu = setLocalMtu()
	}
	fmt.Printf("Using path:\n  %s\n", pathStr)

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

func choosePath() *sciond.PathReplyEntry {
	var paths []*sciond.PathReplyEntry
	var pathIndex uint64

	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(cmn.Local.IA, cmn.Remote.IA)

	if len(pathSet) == 0 {
		return nil
	}
	for _, p := range pathSet {
		paths = append(paths, p.Entry)
	}
	if cmn.Interactive {
		fmt.Printf("Available paths to %v\n", cmn.Remote.IA)
		for i := range paths {
			fmt.Printf("[%2d] %s\n", i, paths[i].Path.String())
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
			fmt.Fprintf(os.Stderr, "ERROR: Invalid path index, valid indices range: [0, %v]\n", len(paths))
		}
	}
	return paths[pathIndex]
}

func setPathAndMtu() uint16 {
	cmn.PathEntry = choosePath()
	if cmn.PathEntry == nil {
		cmn.Fatal("No paths available to remote destination")
	}
	cmn.Remote.Path = spath.New(cmn.PathEntry.Path.FwdPath)
	cmn.Remote.Path.InitOffsets()
	cmn.Remote.NextHopHost = cmn.PathEntry.HostInfo.Host()
	cmn.Remote.NextHopPort = cmn.PathEntry.HostInfo.Port
	return cmn.PathEntry.Path.Mtu
}

func setLocalMtu() uint16 {
	// Use local AS MTU when we have no path
	sd := snet.DefNetwork.Sciond()
	c, err := sd.Connect()
	if err != nil {
		cmn.Fatal("Unable to connect to sciond")
	}
	reply, err := c.ASInfo(addr.IA{})
	if err != nil {
		cmn.Fatal("Unable to request AS info to sciond")
	}
	// XXX We expect a single entry in the reply
	return reply.Entries[0].Mtu
}
