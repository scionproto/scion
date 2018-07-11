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

// Simple application for SCION connectivity using the snet library.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
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

var (
	local  snet.Addr
	remote snet.Addr
	file   = flag.String("file", "",
		"File containing the data to send, optional to test larger data")
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
	interval     = flag.Duration("interval", DefaultInterval, "time between pings")
	verbose      = flag.Bool("v", false, "sets verbose output")
	sciondFromIA = flag.Bool("sciondFromIA", false,
		"SCIOND socket path from IA address:ISD-AS")
	fileData []byte
)

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
}

func main() {
	log.AddLogConsFlags()
	validateFlags()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()
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
	if *sciondFromIA {
		if *sciond != "" {
			LogFatal("Only one of -sciond or -sciondFromIA can be specified")
		}
		if local.IA.IsZero() {
			LogFatal("-local flag is missing")
		}
		*sciond = sd.GetDefaultSCIONDPath(&local.IA)
	} else if *sciond == "" {
		*sciond = sd.GetDefaultSCIONDPath(nil)
	}
	if *count < 0 || *count > MaxPings {
		LogFatal("Invalid count", "min", 0, "max", MaxPings, "actual", *count)
	}
	if *file != "" {
		var err error
		fileData, err = ioutil.ReadFile(*file)
		if err != nil {
			LogFatal("Could not read data file")
		}
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

func Send(qstream quic.Stream) {
	reqMsg := requestMsg()
	reqMsgLen := len(reqMsg)
	payload := make([]byte, reqMsgLen+TSLen)
	copy(payload, reqMsg)
	for i := 0; i < *count || *count == 0; i++ {
		if i != 0 && *interval != 0 {
			time.Sleep(*interval)
		}

		// Send ping message to destination
		before := time.Now()
		common.Order.PutUint64(payload[reqMsgLen:], uint64(before.UnixNano()))
		written, err := qstream.Write(payload)
		if err != nil {
			qer := qerr.ToQuicError(err)
			if qer.ErrorCode == qerr.NetworkIdleTimeout {
				log.Debug("The connection timed out due to no network activity")
				break
			}
			log.Error("Unable to write", "err", err)
			continue
		}
		if written != reqMsgLen+TSLen {
			log.Error("Wrote incomplete message", "expected", reqMsgLen+TSLen,
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

func Read(qstream quic.Stream) {
	// Receive pong message (with final timeout)
	replyMsg := replyMsg()
	b := make([]byte, len(replyMsg)+TSLen)
	replyMsgLen := len(replyMsg)
	for i := 0; i < *count || *count == 0; i++ {
		read, err := io.ReadFull(qstream, b)
		after := time.Now()
		if err != nil {
			qer := qerr.ToQuicError(err)
			if qer.ErrorCode == qerr.PeerGoingAway {
				log.Debug("Quic peer disconnected")
				break
			}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Debug("ReadDeadline missed", "err", err)
				// ReadDeadline is only set after we are done writing
				// and we don't want to wait indefinitely for the remaining responses
				break
			}
			log.Error("Unable to read", "err", err)
			continue
		}
		if read < replyMsgLen {
			fmt.Println("Reply too short", "expectedLen", len(replyMsg),
				"readLen", read)
			continue
		}
		if read < replyMsgLen+TSLen {
			fmt.Println("Received bad message missing timestamp")
			continue
		}
		if !bytes.Equal(b[:replyMsgLen], replyMsg) {
			fmt.Println("Received different message than expected", "expectedLen", len(replyMsg),
				"readLen", read)
			continue
		}
		before := time.Unix(0, int64(common.Order.Uint64(b[replyMsgLen:replyMsgLen+TSLen])))
		elapsed := after.Sub(before).Round(time.Microsecond)
		if *verbose {
			fmt.Printf("[%s]\tReceived %d bytes from %v: seq=%d RTT=%s\n",
				before.Format(common.TimeFmt), read, &remote, i, elapsed)
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
			// Accept failing means the socket is unusable.
			break
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

func handleClient(qsess quic.Session) {
	defer qsess.Close(nil)
	qstream, err := qsess.AcceptStream()
	if err != nil {
		log.Error("Unable to accept quic stream", "err", err)
		return
	}
	defer qstream.Close()

	reqMsg := requestMsg()
	b := make([]byte, len(reqMsg)+TSLen)
	reqMsgLen := len(reqMsg)
	for {
		// Receive ping message
		read, err := io.ReadFull(qstream, b)
		if err != nil {
			qer := qerr.ToQuicError(err)
			if qer.ErrorCode == qerr.PeerGoingAway {
				log.Debug("Quic peer disconnected")
				break
			}
			log.Error("Unable to read", "err", err)
			break
		}
		if !bytes.Equal(b[:reqMsgLen], reqMsg) {
			fmt.Println("Received different message than expected",
				"expectedLen", reqMsgLen, "readLen", read)
		}
		// extract timestamp
		ts := common.Order.Uint64(b[reqMsgLen:])

		// Send pong message
		replyMsg := replyMsg()
		replyMsgLen := len(replyMsg)
		copy(b[:replyMsgLen], replyMsg)
		common.Order.PutUint64(b[replyMsgLen:], ts)
		written, err := qstream.Write(b[:replyMsgLen+TSLen])
		if err != nil {
			log.Error("Unable to write", "err", err)
			continue
		} else if written != replyMsgLen+TSLen {
			log.Error("Wrote incomplete message",
				"expected", replyMsgLen+TSLen, "actual", written)
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

func requestMsg() []byte {
	return msg(ReqMsg)
}

func replyMsg() []byte {
	return msg(ReplyMsg)
}

func msg(prefix string) []byte {
	res := make([]byte, 0, len(prefix)+len(fileData))
	res = append(res, []byte(prefix)...)
	return append(res, fileData...)
}
