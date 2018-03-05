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

	log "github.com/inconshreveable/log15"

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
	logLevel = flag.String("logLevel", "info", "Console logging level")
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

	logSetup()
	defer logPanicAndExit()

	if local.IA == nil {
		logFatal("Missing local address")
	}
	if *sciondPath == "" {
		*sciondPath = GetDefaultSCIONDPath(local.IA)
	}
	// Initialize default SCION networking context
	if err := snet.Init(local.IA, *sciondPath, *dispatcher); err != nil {
		logFatal("Unable to initialize SCION network", "err", err)
	}
	log.Debug("SCION network successfully initialized")

	// scmp-tool does not uses ports, thus they should not be set
	// Still, the user could set port as 0 ie, ISD-AS,[host]:0 and be valid
	if local.L4Port != 0 {
		logFatal("Invalid local port", "local port", local.L4Port)
	}
	if remote.L4Port != 0 {
		logFatal("Invalid remote port", "remote port", remote.L4Port)
	}
	// Connect directly to the dispatcher
	address := &reliable.AppAddr{Addr: local.Host, Port: 0}
	conn, port, err := reliable.Register(*dispatcher, local.IA, address, nil, addr.SvcNone)
	if err != nil {
		logFatal("Unable to register with the dispatcher", "err", err, "addr", local)
	}
	defer conn.Close()
	log.Debug("Registered with dispatcher", "ia", local.IA, "host", address.Addr.String(), "port", port)

	var pathEntry *sciond.PathReplyEntry
	// If remote is not in local AS, we need a path!
	if !remote.IA.Eq(local.IA) {
		pathEntry = choosePath(*interactive)
		if pathEntry == nil {
			logFatal("No paths available to remote destination")
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

func SendPkts(wg *sync.WaitGroup, conn *reliable.Conn, s *scmpPkt) {
	defer wg.Done()
	defer logPanicAndExit()

	nextPktTS := time.Now()
	b := make(common.RawBytes, 1<<10)

	nhAddr := reliable.AppAddr{Addr: remote.NextHopHost, Port: remote.NextHopPort}
	if remote.NextHopHost == nil {
		nhAddr = reliable.AppAddr{Addr: remote.Host, Port: overlay.EndhostPort}
	}
	log.Debug("Path next Hop:", "Host", nhAddr.Addr, "Port", nhAddr.Port)
	for {
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(s.pkt, b)
		if err != nil {
			log.Error("Unable to serialize SCION packet", "err", err)
			break
		}
		written, err := conn.WriteTo(b[:pktLen], nhAddr)
		if err != nil {
			log.Error("Unable to write", "err", err)
			break
		} else if written != pktLen {
			log.Error("Wrote incomplete message", "expected", len(b), "actual", written)
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
	defer logPanicAndExit()

	b := make([]byte, 1<<10)

	for {
		pktLen, err := conn.Read(b)
		if err != nil {
			log.Error("Unable to read", "err", err)
			break
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(s.pkt, b[:pktLen])
		if err != nil {
			log.Error("SCION packet parse error", "err", err)
			break
		}
		err = validatePkt(s)
		if err != nil {
			log.Error("Unexpected SCMP Packet", "err", err)
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
		log.Info(fmt.Sprintf("Available paths to %v", remote.IA))
		for i := range pathIndeces {
			log.Info(fmt.Sprintf("[%2d] %s\n", i, pathSet[pathIndeces[i]].Entry.Path.String()))
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			log.Info(fmt.Sprintf("Choose path: "))
			pathIndexStr, _ := reader.ReadString('\n')
			var err error
			pathIndex, err = strconv.ParseUint(pathIndexStr[:len(pathIndexStr)-1], 10, 64)
			if err == nil && pathIndex < i {
				break
			}
			log.Error("Invalid path index. Valid indeces:", "min", 0, "max", i-1)
		}
	}
	log.Info(fmt.Sprintf("Using path:\n  %s\n", pathSet[pathIndeces[pathIndex]].Entry.Path.String()))
	return pathSet[pathIndeces[pathIndex]].Entry
}
