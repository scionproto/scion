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
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	DefaultInterval = 1 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxEchoes       = 1 << 16
)

func GetDefaultSCIONDPath(ia *addr.ISD_AS) string {
	return fmt.Sprintf("/run/shm/sciond/sd%v.sock", ia)
}

var (
	id          = flag.String("id", "echo", "Element ID")
	interactive = flag.Bool("i", false, "Interactive mode")
	sciondPath  = flag.String("sciond", "", "Path to sciond socket")
	dispatcher  = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"Path to dispatcher socket")
	interval = flag.Duration("interval", DefaultInterval, "time between packets")
	count    = flag.Uint("c", 10, "Total number of packet to send (ignored if not echo")
	sTypeStr = &sType
	local    snet.Addr
	remote   snet.Addr
	rnd      *rand.Rand
)

var sType string = "echo"

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.Parse()
}

func main() {
	var wg sync.WaitGroup

	if local.IA == nil {
		fatal("Missing local address")
	}
	if *sciondPath == "" {
		*sciondPath = GetDefaultSCIONDPath(local.IA)
	}
	// Initialize default SCION networking context
	if err := snet.Init(local.IA, *sciondPath, *dispatcher); err != nil {
		fatal("Unable to initialize SCION network", "err", err)
	}
	// Connect directly to the dispatcher
	address := &reliable.AppAddr{Addr: local.Host, Port: 0}
	conn, _, err := reliable.Register(*dispatcher, local.IA, address, nil, addr.SvcNone)
	if err != nil {
		fatal("Unable to register with the dispatcher", "err", err, "addr", local)
	}
	defer conn.Close()

	validate()

	var pathEntry *sciond.PathReplyEntry
	// If remote is not in local AS, we need a path!
	if !remote.IA.Eq(local.IA) {
		pathEntry = choosePath(*interactive)
		if pathEntry == nil {
			fatal("No paths available to remote destination")
		}
		remote.Path = spath.New(pathEntry.Path.FwdPath)
		remote.Path.InitOffsets()
		remote.NextHopHost = pathEntry.HostInfo.Host()
		remote.NextHopPort = pathEntry.HostInfo.Port
	}

	seed := rand.NewSource(time.Now().UnixNano())
	rnd = rand.New(seed)

	var send, recv scmpPkt
	initSCMP(&send, &recv, *sTypeStr, *count, pathEntry)

	wg.Add(2)
	go RecvPkts(&wg, conn, &recv)
	go SendPkts(&wg, conn, &send)

	wg.Wait()
}

func validate() {
	if local.IA == nil {
		fatal("Invalid local address")
	}
	if remote.IA == nil {
		fatal("Invalid remote address")
	}
	// scmp-tool does not uses ports, thus they should not be set
	// Still, the user could set port as 0 ie, ISD-AS,[host]:0 and be valid
	if local.L4Port != 0 {
		fatal("Invalid local port", "local port", local.L4Port)
	}
	if remote.L4Port != 0 {
		fatal("Invalid remote port", "remote port", remote.L4Port)
	}
}

func SendPkts(wg *sync.WaitGroup, conn *reliable.Conn, s *scmpPkt) {
	defer wg.Done()

	nextPktTS := time.Now()
	b := make(common.RawBytes, 1<<10)

	nhAddr := reliable.AppAddr{Addr: remote.NextHopHost, Port: remote.NextHopPort}
	if remote.NextHopHost == nil {
		nhAddr = reliable.AppAddr{Addr: remote.Host, Port: overlay.EndhostPort}
	}
	for {
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(s.pkt, b)
		if err != nil {
			fmt.Printf("ERROR: Unable to serialize SCION packet %s\n", err.Error())
			break
		}
		written, err := conn.WriteTo(b[:pktLen], nhAddr)
		if err != nil {
			fmt.Printf("ERROR: Unable to write %s\n", err.Error())
			break
		} else if written != pktLen {
			fmt.Printf("ERROR: Wrote incomplete message. written=%v, expected=%v\n", len(b), written)
			break
		}
		nextPktTS = nextPktTS.Add(*interval)
		if !sendNext(s, nextPktTS) {
			break
		}
		sleepTime := time.Until(nextPktTS)
		time.Sleep(sleepTime)
	}
}

func RecvPkts(wg *sync.WaitGroup, conn *reliable.Conn, s *scmpPkt) {
	defer wg.Done()

	b := make([]byte, 1<<10)

	for {
		pktLen, err := conn.Read(b)
		if err != nil {
			fmt.Printf("ERROR: Unable to read %s\n", err.Error())
			break
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(s.pkt, b[:pktLen])
		if err != nil {
			fmt.Printf("ERROR: SCION packet parse error %s\n", err.Error())
			break
		}
		err = validatePkt(s)
		if err != nil {
			fmt.Printf("ERROR: Unexpected SCMP Packet %s\n", err.Error())
			break
		}
		prettyPrint(s, pktLen, now)
		if !recvNext(s) {
			break
		}
	}
}

func choosePath(interactive bool) *sciond.PathReplyEntry {
	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(local.IA, remote.IA)
	pathIndeces := make(map[uint64]pathmgr.PathKey)
	pathIndex := uint64(0)
	i := uint64(0)

	if len(pathSet) == 0 {
		return nil
	}
	for k := range pathSet {
		pathIndeces[i] = k
		i++
	}
	if interactive {
		fmt.Printf("Available paths to %v\n", remote.IA)
		for i := range pathIndeces {
			fmt.Printf("[%2d] %s\n", i, pathSet[pathIndeces[i]].Entry.Path.String())
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("Choose path: ")
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIndex, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && pathIndex < i {
				break
			}
			fmt.Printf("ERROR: Invalid path index, valid indices range: [0, %v]\n", i-1)
		}
	}
	fmt.Printf("Using path:\n  %s\n", pathSet[pathIndeces[pathIndex]].Entry.Path.String())
	return pathSet[pathIndeces[pathIndex]].Entry
}

func fatal(msg string, a ...interface{}) {
	fmt.Printf("CRIT: "+msg+"\n", a...)
	os.Exit(1)
}
