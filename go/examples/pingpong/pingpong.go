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
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	log "github.com/inconshreveable/log15"
	//"github.com/lucas-clemente/quic-go"
	//"github.com/lucas-clemente/quic-go/qerr"

	"github.com/scionproto/scion/go/lib/addr"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
)

const (
	DefaultInterval = 2 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxPings        = 1 << 16
	ReqMsg          = "ping!"
	ReplyMsg        = "pong!"
)

func GetDefaultSCIONDPath(ia addr.IA) string {
	return fmt.Sprintf("/run/shm/sciond/sd%v.sock", ia)
}

var (
	local      snet.Addr
	remote     snet.Addr
	id         = flag.String("id", "pingpong", "Element ID")
	mode       = flag.String("mode", "client", "Run in client or server mode")
	sciond     = flag.String("sciond", "", "Path to sciond socket")
	dispatcher = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"Path to dispatcher socket")
	count = flag.Int("count", 0,
		fmt.Sprintf("Number of pings, between 0 and %d; a count of 0 means infinity", MaxPings))
	timeout = flag.Duration("timeout", DefaultTimeout,
		"Timeout for the ping response")
	interval = flag.Duration("interval", DefaultInterval, "time between pings")
)

func init() {
	flag.Var((*Address)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*Address)(&remote), "remote", "(Mandatory for clients) address to connect to")
}

func main() {
	validateFlags()
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	switch *mode {
	case "client":
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

	b := make([]byte, 1<<12)
	for i := 0; i < *count || *count == 0; i++ {
		if i != 0 && *interval != 0 {
			time.Sleep(*interval)
		}

		// Send ping message to destination
		before := time.Now()
		written, err := qstream.Write([]byte(ReqMsg))
		if err != nil {
			//qer := qerr.ToQuicError(err)
			//if qer.ErrorCode == qerr.NetworkIdleTimeout {
			//	log.Debug("The connection timed out due to no network activity")
			//	break
			//}
			log.Error("Unable to write", "err", err)
			continue
		}
		if written != len(ReqMsg) {
			log.Error("Wrote incomplete message", "expected", len(ReqMsg),
				"actual", written)
			continue
		}

		// Receive pong message with timeout
		err = qstream.SetReadDeadline(time.Now().Add(*timeout))
		if err != nil {
			LogFatal("SetReadDeadline failed", "err", err)
		}
		read, err := qstream.Read(b)
		if err != nil {
			//qer := qerr.ToQuicError(err)
			//if qer.ErrorCode == qerr.PeerGoingAway {
			//	log.Debug("Quic peer disconnected")
			//	break
			//}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Debug("ReadDeadline missed", "err", err)
				continue
			}
			log.Error("Unable to read", "err", err)
			continue
		}
		if string(b[:read]) != ReplyMsg {
			fmt.Println("Received bad message", "expected", ReplyMsg,
				"actual", string(b[:read]))
		}
		after := time.Now()
		elapsed := after.Sub(before)
		fmt.Printf("%d bytes from %v: seq=%d time=%s\n", read, &remote, i, elapsed)
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
			LogFatal("Unable to accept quic session", "err", err)
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

func handleClient( /*qsess quic.Session*/ ) {
	qstream, err := qsess.AcceptStream()
	if err != nil {
		LogFatal("Unable to accept quic stream", "err", err)
	}

	b := make([]byte, 1<<12)
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
		if string(b[:read]) != ReqMsg {
			fmt.Println("Received bad message", "expected", ReqMsg,
				"actual", string(b[:read]))
		}

		// Send pong message
		written, err := qstream.Write([]byte(ReplyMsg))
		if err != nil {
			LogFatal("Unable to write", "err", err)
		} else if written != len(ReplyMsg) {
			LogFatal("Wrote incomplete message", "expected", len(ReplyMsg), "actual", written)
		}
	}
}

type Address snet.Addr

func (a *Address) String() string {
	return (*snet.Addr)(a).String()
}

func (a *Address) Set(s string) error {
	other, err := snet.AddrFromString(s)
	if err != nil {
		return err
	}
	a.IA, a.Host, a.L4Port = other.IA, other.Host, other.L4Port
	return nil
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}
