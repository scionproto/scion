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
	sTypeStr  = flag.String("t", "echo", "SCMP Type: echo |  rp | recordpath")
	local     snet.Addr
	remote    snet.Addr
	bind      snet.Addr
	rnd       *rand.Rand
	pathEntry *sciond.PathReplyEntry
	mtu       uint16
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

	if *sciondPath == "" {
		*sciondPath = GetDefaultSCIONDPath(local.IA)
	}
	// Initialize default SCION networking context
	if err := snet.Init(local.IA, *sciondPath, *dispatcher); err != nil {
		fatal("Unable to initialize SCION network\nerr=%v", err)
	}
	// Connect directly to the dispatcher
	address := &reliable.AppAddr{Addr: local.Host}
	var bindAddress *reliable.AppAddr
	if bind.Host != nil {
		bindAddress = &reliable.AppAddr{Addr: bind.Host}
	}
	conn, _, err := reliable.Register(*dispatcher, local.IA, address, bindAddress, addr.SvcNone)
	if err != nil {
		fatal("Unable to register with the dispatcher addr=%s\nerr=%v", local, err)
	}
	defer conn.Close()

	// If remote is not in local AS, we need a path!
	var pathStr string
	if !remote.IA.Eq(local.IA) {
		mtu = setPathAndMtu()
		pathStr = pathEntry.Path.String()
	} else {
		mtu = setLocalMtu()
		pathStr = "None"
	}
	fmt.Printf("Using path:\n  %s\n", pathStr)

	seed := rand.NewSource(time.Now().UnixNano())
	rnd = rand.New(seed)

	var ctx scmpCtx
	initSCMP(&ctx, *sTypeStr, *count, pathEntry)

	ch := make(chan time.Time, 20)
	wg.Add(2)
	go RecvPkts(&wg, conn, &ctx, ch)
	go SendPkts(&wg, conn, &ctx, ch)

	wg.Wait()

	ret := 0
	if ctx.sent != ctx.recv {
		ret = 1
	}

	os.Exit(ret)
}

func SendPkts(wg *sync.WaitGroup, conn *reliable.Conn, ctx *scmpCtx, ch chan time.Time) {
	defer wg.Done()
	defer close(ch)

	b := make(common.RawBytes, mtu)

	nhAddr := reliable.AppAddr{Addr: remote.NextHopHost, Port: remote.NextHopPort}
	if remote.NextHopHost == nil {
		nhAddr = reliable.AppAddr{Addr: remote.Host, Port: overlay.EndhostPort}
	}
	nextPktTS := time.Now()
	ticker := time.NewTicker(*interval)
	for ; true; nextPktTS = <-ticker.C {
		updatePktTS(ctx, nextPktTS)
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(ctx.pktS, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
			break
		}
		written, err := conn.WriteTo(b[:pktLen], &nhAddr)
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
		ctx.sent += 1
		// Update packet fields
		updatePkt(ctx)
		if !morePkts(ctx) {
			break
		}
	}
}

func RecvPkts(wg *sync.WaitGroup, conn *reliable.Conn, ctx *scmpCtx, ch chan time.Time) {
	defer wg.Done()

	b := make(common.RawBytes, mtu)

	start := time.Now()
	nextTimeout := start
	for {
		nextPktTS, ok := <-ch
		if ok {
			nextTimeout = nextPktTS.Add(*timeout)
			conn.SetReadDeadline(nextTimeout)
		} else if ctx.recv == ctx.sent || nextTimeout.Before(time.Now()) {
			break
		}
		pktLen, err := conn.Read(b)
		if err != nil {
			e, ok := err.(*net.OpError)
			if ok && e.Timeout() {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(ctx.pktR, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
			break
		}
		err = validatePkt(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation error: %v\n", err)
			break
		}
		ctx.recv += 1
		prettyPrint(ctx, pktLen, now)
	}
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
		ctx.sent, ctx.recv, 100-ctx.recv*100/ctx.sent, time.Since(start).Round(time.Microsecond))
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
	return paths[pathIndex]
}

func validate() {
	if local.Host == nil {
		fatal("Invalid local address")
	}
	if remote.Host == nil {
		fatal("Invalid remote address")
	}
	// scmp-tool does not use ports, thus they should not be set
	// Still, the user could set port as 0 ie, ISD-AS,[host]:0 and be valid
	if local.L4Port != 0 {
		fatal("Local port should not be provided")
	}
	if remote.L4Port != 0 {
		fatal("Remote port should not be provided")
	}
}

func setPathAndMtu() uint16 {
	pathEntry = choosePath(*interactive)
	if pathEntry == nil {
		fatal("No paths available to remote destination")
	}
	remote.Path = spath.New(pathEntry.Path.FwdPath)
	remote.Path.InitOffsets()
	remote.NextHopHost = pathEntry.HostInfo.Host()
	remote.NextHopPort = pathEntry.HostInfo.Port
	return pathEntry.Path.Mtu
}

func setLocalMtu() uint16 {
	// Use local AS MTU when we have no path
	sd := snet.DefNetwork.Sciond()
	c, err := sd.Connect()
	if err != nil {
		fatal("Unable to connect to sciond")
	}
	reply, err := c.ASInfo(addr.IA{})
	if err != nil {
		fatal("Unable to request AS info to sciond")
	}
	// XXX We expect a single entry in the reply
	return reply.Entries[0].Mtu
}

func fatal(msg string, a ...interface{}) {
	fmt.Printf("CRIT: "+msg+"\n", a...)
	os.Exit(1)
}
