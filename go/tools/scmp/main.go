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
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/overlay"
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

func GetDefaultSCIONDPath(ia addr.IA) string {
	return fmt.Sprintf("/run/shm/sciond/sd%v.sock", ia)
}

var (
	id          = flag.String("id", "echo", "Element ID")
	interactive = flag.Bool("i", false, "Interactive mode")
	sciondPath  = flag.String("sciond", "", "Path to sciond socket")
	dispatcher  = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"Path to dispatcher socket")
	interval  = flag.Duration("interval", DefaultInterval, "time between packets")
	timeout   = flag.Duration("timeout", DefaultTimeout, "timeout per packet")
	count     = flag.Uint("c", 0, "Total number of packet to send (ignored if not echo)")
	sTypeStr  = &sType
	local     snet.Addr
	remote    snet.Addr
	bind      snet.Addr
	rnd       *rand.Rand
	pathEntry *sciond.PathReplyEntry
)

var sType string = "echo"

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.Var((*snet.Addr)(&bind), "bind", "address to bind to, if running behind NAT")
}

func main() {
	var wg sync.WaitGroup

	flag.Parse()
	validate()

	if local.Host == nil {
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
	address := &reliable.AppAddr{Addr: local.Host}
	bindAddress := &reliable.AppAddr{Addr: bind.Host}
	if bind.Host == nil {
		bindAddress = nil
	}
	conn, _, err := reliable.Register(*dispatcher, local.IA, address, bindAddress, addr.SvcNone)
	if err != nil {
		fatal("Unable to register with the dispatcher", "err", err, "addr", local)
	}
	defer conn.Close()

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

	var send, recv scmpCtx
	initSCMP(&send, &recv, *sTypeStr, *count, pathEntry)

	ch := make(chan time.Time, 20)
	wg.Add(2)
	go RecvPkts(&wg, conn, &recv, ch)
	go SendPkts(&wg, conn, &send, ch)

	wg.Wait()

	ret := 0
	if send.num != recv.num {
		ret = 1
	}

	os.Exit(ret)
}

func validate() {
	if local.Host == nil {
		fatal("Invalid local address")
	}
	if remote.Host == nil {
		fatal("Invalid remote address")
	}
	// scmp-tool does not uses ports, thus they should not be set
	// Still, the user could set port as 0 ie, ISD-AS,[host]:0 and be valid
	if local.L4Port != 0 {
		fatal("Local port should not be provided")
	}
	if remote.L4Port != 0 {
		fatal("Remote port should not be provided")
	}
}

func sendPKt(conn *reliable.Conn, s *scmpCtx, b common.RawBytes) {
}

func SendPkts(wg *sync.WaitGroup, conn *reliable.Conn, s *scmpCtx, ch chan time.Time) {
	defer wg.Done()
	defer close(ch)

	b := make(common.RawBytes, pathEntry.Path.Mtu)

	nhAddr := reliable.AppAddr{Addr: remote.NextHopHost, Port: remote.NextHopPort}
	if remote.NextHopHost == nil {
		nhAddr = reliable.AppAddr{Addr: remote.Host, Port: overlay.EndhostPort}
	}
	nextPktTS := time.Now()
	ticker := time.NewTicker(*interval)
	for ; true; nextPktTS = <-ticker.C {
		updatePktTS(s, nextPktTS)
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(s.pkt, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
			break
		}
		written, err := conn.WriteTo(b[:pktLen], nhAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to write %v\n", err)
			break
		} else if written != pktLen {
			fmt.Fprintf(os.Stderr, "ERROR: Wrote incomplete message. written=%d, expected=%d\n",
				len(b), written)
			break
		}
		// Notify the receiver
		ch <- nextPktTS
		// Update packet fields
		updatePkt(s)
		if !morePkts(s) {
			break
		}
	}
}

func RecvPkts(wg *sync.WaitGroup, conn *reliable.Conn, s *scmpCtx, ch chan time.Time) {
	defer wg.Done()
	var sent uint64

	b := make(common.RawBytes, pathEntry.Path.Mtu)

	start := time.Now()
	nextTimeout := start
	for {
		nextPktTS, ok := <-ch
		if ok {
			sent += 1
			nextTimeout = nextPktTS.Add(*timeout)
			conn.SetReadDeadline(nextTimeout)
		} else if s.num == sent || nextTimeout.Before(time.Now()) {
			break
		}
		pktLen, err := conn.Read(b)
		if err != nil {
			e, ok := err.(*net.OpError)
			if ok && e.Timeout() {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read %v\n", err)
				break
			}
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(s.pkt, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error %v\n", err)
			break
		}
		err = validatePkt(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unexpected SCMP Packet %v\n", err)
			break
		}
		s.num += 1
		prettyPrint(s, pktLen, now)
	}
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
		sent, s.num, 100-s.num*100/sent, time.Now().Sub(start))
}

func choosePath(interactive bool) *sciond.PathReplyEntry {
	var paths []*sciond.PathReplyEntry
	var pathIndex uint64

	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(local.IA, remote.IA)

	if len(pathSet) == 0 {
		return nil
	}
	for _, p := range pathSet {
		paths = append(paths, p.Entry)
	}
	if interactive {
		fmt.Printf("Available paths to %v\n", remote.IA)
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
	fmt.Printf("Using path:\n  %s\n", paths[pathIndex].Path.String())
	return paths[pathIndex]
}

func fatal(msg string, a ...interface{}) {
	fmt.Printf("CRIT: "+msg+"\n", a...)
	os.Exit(1)
}
