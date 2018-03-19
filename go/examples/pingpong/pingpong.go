// Copyright 2017 ETH Zurich
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

// +build ignore

// Simple application for SCION connectivity using the snet library.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	log "github.com/inconshreveable/log15"
	//"github.com/lucas-clemente/quic-go"
	//"github.com/lucas-clemente/quic-go/qerr"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	liblog "github.com/scionproto/scion/go/lib/log"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	DefaultInterval = 1 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxPings        = 1 << 16
	ReqMsg          = "ping!" // ReqMsg and ReplyMsg length need to be the same
	ReplyMsg        = "pong!"
	TSLen           = 8
)

func GetDefaultSCIONDPath(ia addr.IA) string {
	return fmt.Sprintf("/run/shm/sciond/sd%v.sock", ia)
}

var (
	local       snet.Addr
	remote      snet.Addr
	interactive = flag.Bool("i", false, "Interactive mode")
	id          = flag.String("id", "pingpong", "Element ID")
	mode        = flag.String("mode", "client", "Run in client or server mode")
	sciond      = flag.String("sciond", "", "Path to sciond socket")
	dispatcher  = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"Path to dispatcher socket")
	count = flag.Int("count", 0,
		fmt.Sprintf("Number of pings, between 0 and %d; a count of 0 means infinity", MaxPings))
	timeout = flag.Duration("timeout", DefaultTimeout,
		"Timeout for the ping response")
	interval = flag.Duration("interval", DefaultInterval, "time between pings")
	verbose  = flag.Bool("v", false, "sets verbose output")
)

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
}

func main() {
	liblog.AddDefaultLogFlags()
	validateFlags()
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	switch *mode {
	case "client":
		if remote.Host == nil {
			LogFatal("Missing remote address")
		}
		if remote.L4Port == 0 {
			LogFatal("Invalid remote port", "remote port", remote.L4Port)
		}
		Client()
	case "server":
		Server()
	}
}

func validateFlags() {
	flag.Parse()
	if *mode != "client" && *mode != "server" {
		LogFatal("Unknown mode, must be either 'client' or 'server'")
	}
	if *mode == "client" && remote.Host == nil {
		LogFatal("Missing remote address")
	}
	if local.Host == nil {
		LogFatal("Missing local address")
	}
	if *sciond == "" {
		*sciond = GetDefaultSCIONDPath(local.IA)
	}
	if *count < 0 || *count > MaxPings {
		LogFatal("Invalid count", "min", 0, "max", MaxPings, "actual", *count)
	}
}

// Client dials to a remote SCION address and repeatedly sends ping messages
// while receiving pong messages. For each successful ping-pong, a message
// with the round trip time is printed. On errors (including timeouts),
// the Client exits.
func Client() {
	initNetwork()

	// Needs to happen before DialSCION, as it will 'copy' the remote to the connection.
	// If remote is not in local AS, we need a path!
	if !remote.IA.Eq(local.IA) {
		pathEntry := choosePath(*interactive)
		if pathEntry == nil {
			LogFatal("No paths available to remote destination")
		}
		remote.Path = spath.New(pathEntry.Path.FwdPath)
		remote.Path.InitOffsets()
		remote.NextHopHost = pathEntry.HostInfo.Host()
		remote.NextHopPort = pathEntry.HostInfo.Port
	}

	// Connect to remote address. Note that currently the SCION library
	// does not support automatic binding to local addresses, so the local
	// IP address needs to be supplied explicitly. When supplied a local
	// port of 0, DialSCION will assign a random free local port.
	qsess, err := squic.DialSCION(nil, &local, &remote)
	if err != nil {
		LogFatal("Unable to dial", "err", err)
	}
	defer qsess.Close(nil)

	qstream, err := qsess.OpenStreamSync()
	if err != nil {
		LogFatal("quic OpenStream failed", "err", err)
	}
	defer qstream.Close()
	log.Debug("Quic stream opened", "local", &local, "remote", &remote)
	go Send(qstream)
	Read(qstream)
}

func Send( /* qstream quic.Stream */ ) {
	reqMsgLen := len(ReqMsg)
	payload := make([]byte, reqMsgLen+TSLen)
	copy(payload[0:], ReqMsg)
	for i := 0; i < *count || *count == 0; i++ {
		if i != 0 && *interval != 0 {
			time.Sleep(*interval)
		}

		// Send ping message to destination
		before := time.Now()
		common.Order.PutUint64(payload[reqMsgLen:], uint64(before.UnixNano()))
		written, err := qstream.Write(payload[:])
		if err != nil {
			//qer := qerr.ToQuicError(err)
			//if qer.ErrorCode == qerr.NetworkIdleTimeout {
			//	log.Debug("The connection timed out due to no network activity")
			//	break
			//}
			log.Error("Unable to write", "err", err)
			continue
		}
		if written != len(ReqMsg)+TSLen {
			log.Error("Wrote incomplete message", "expected", len(ReqMsg)+TSLen,
				"actual", written)
			continue
		}
	}
	// After sending the last ping, set a ReadDeadline on the stream
	err := qstream.SetReadDeadline(time.Now().Add(*timeout))
	if err != nil {
		LogFatal("SetReadDeadline failed", "err", err)
	}
}

func Read( /* qstream quic.Stream */ ) {
	// Receive pong message (with final timeout)
	b := make([]byte, 1<<12)
	replyMsgLen := len(ReplyMsg)
	for i := 0; i < *count || *count == 0; i++ {
		read, err := qstream.Read(b)
		after := time.Now()
		if err != nil {
			//qer := qerr.ToQuicError(err)
			//if qer.ErrorCode == qerr.PeerGoingAway {
			//	log.Debug("Quic peer disconnected")
			//	break
			//}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Debug("ReadDeadline missed", "err", err)
				// ReadDeadline is only set after we are done writing
				// and we don't want to wait indefinitely for the remaining responses
				break
			}
			log.Error("Unable to read", "err", err)
			continue
		}
		if read < replyMsgLen || string(b[:replyMsgLen]) != ReplyMsg {
			fmt.Println("Received bad message", "expected", ReplyMsg,
				"actual", string(b[:read]))
			continue
		}
		if read < replyMsgLen+TSLen {
			fmt.Println("Received bad message missing timestamp",
				"actual", string(b[:read]))
			continue
		}
		before := time.Unix(0, int64(common.Order.Uint64(b[replyMsgLen:replyMsgLen+TSLen])))
		elapsed := after.Sub(before)
		if *verbose {
			fmt.Printf("[%s]\tReceived %d bytes from %v: seq=%d RTT=%s\n",
				before.Unix(), read, &remote, i, elapsed)
		} else {
			fmt.Printf("Received %d bytes from %v: seq=%d RTT=%s\n",
				read, &remote, i, elapsed)
		}
	}
}

// Server listens on a SCION address and replies to any ping message.
// On any error, the server exits.
func Server() {
	initNetwork()

	// Listen on SCION address
	qsock, err := squic.ListenSCION(nil, &local)
	if err != nil {
		LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Listening", "local", qsock.Addr())
	for {
		qsess, err := qsock.Accept()
		if err != nil {
			log.Error("Unable to accept quic session", "err", err)
			continue
		}
		log.Debug("Quic session accepted", "src", qsess.RemoteAddr())
		go handleClient(qsess)
	}
}

func initNetwork() {
	// Initialize default SCION networking context
	if err := snet.Init(local.IA, *sciond, *dispatcher); err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	log.Debug("SCION network successfully initialized")
	if err := squic.Init("", ""); err != nil {
		LogFatal("Unable to initialize QUIC/SCION", "err", err)
	}
	log.Debug("QUIC/SCION successfully initialized")
}

func handleClient( /* qsess quic.Session */ ) {
	defer qsess.Close(nil)
	qstream, err := qsess.AcceptStream()
	defer qstream.Close()
	if err != nil {
		log.Error("Unable to accept quic stream", "err", err)
		return
	}

	b := make([]byte, 1<<12)
	reqMsgLen := len(ReqMsg)
	for {
		// Receive ping message
		read, err := qstream.Read(b)
		if err != nil {
			//qer := qerr.ToQuicError(err)
			//if qer.ErrorCode == qerr.PeerGoingAway {
			//	log.Debug("Quic peer disconnected")
			//	break
			//}
			log.Error("Unable to read", "err", err)
			break
		}
		if string(b[:reqMsgLen]) != ReqMsg {
			fmt.Println("Received bad message", "expected", ReqMsg,
				"actual", string(b[:reqMsgLen]), "full", string(b[:read]))
		}
		// extract timestamp
		ts := common.Order.PutUint64(b[reqMsgLen:])

		// Send pong message
		replyMsgLen := len(ReplyMsg)
		copy(b[:replyMsgLen], ReplyMsg)
		common.Order.PutUint64(b[replyMsgLen:], ts)
		written, err := qstream.Write(b[:replyMsgLen+TSLen])
		if err != nil {
			log.Error("Unable to write", "err", err)
			continue
		} else if written != len(ReplyMsg)+TSLen {
			log.Error("Wrote incomplete message",
				"expected", len(ReplyMsg)+TSLen, "actual", written)
			continue
		}
	}
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func choosePath(interactive bool) *sd.PathReplyEntry {
	var paths []*sd.PathReplyEntry
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
