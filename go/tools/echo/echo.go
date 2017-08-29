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

// Simple echo application for SCION connectivity tests.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	log15 "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/snet"
)

const (
	DefaultInterval = 2 * time.Second
	DefaultTimeout  = 2 * time.Second
	MaxEchoes       = 1 << 16
	ReqMsg          = "ping!"
	ReplyMsg        = "pong!"
)

var (
	local      snet.Addr
	remote     snet.Addr
	mode       = flag.String("mode", "client", "Run in client or server mode")
	sciond     = flag.String("sciond", "", "(Mandatory) path to sciond socket")
	dispatcher = flag.String("dispatcher", "", "(Mandatory) path to dispatcher socket")
	count      = flag.Int("count", 0,
		fmt.Sprintf("Number of echoes, between 0 and %d; "+
			"a count of 0 means infinity", MaxEchoes))
	interval = flag.Duration("interval", DefaultInterval, "time between echoes")
)

func init() {
	flag.Var((*Address)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*Address)(&remote), "remote", "(Mandatory for clients) address to connect to")
}

func main() {
	validateFlags()

	// Disable logging
	log15.Root().SetHandler(log15.StreamHandler(ioutil.Discard, log15.LogfmtFormat()))

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
		log.Fatal("Unknown mode, must be either 'client' or 'server'")
	}

	if *mode == "client" && remote.Host == nil {
		log.Fatal("Error: missing remote address")
	}

	if *mode == "server" && local.Host == nil {
		log.Fatal("Error: missing local address")
	}

	if *sciond == "" {
		log.Fatal("Error: missing path to sciond")
	}

	if *dispatcher == "" {
		log.Fatal("Error: missing path to dispatcher")
	}

	if *count < 0 || *count > MaxEchoes {
		log.Fatal(fmt.Sprintf("Error: invalid count, must be between 0 and %d", MaxEchoes))
	}
}

// Client dials to a remote SCION address and repeatedly sends echo request
// messages while receiving echo reply messages. For each successful echo, a
// message with the round trip time is printed. On errors (including timeouts),
// the Client exits.
func Client() {
	// Initialize default SCION networking context
	err := snet.Init(local.IA, *sciond, *dispatcher)
	if err != nil {
		log.Fatal("Error: unable to initialize SCION network")
	}
	fmt.Println("SCION network successfully initialized.")

	// Connect to remote address. Note that currently the SCION library
	// does not support automatic binding to local addresses, so the
	// local IP address and port need to be supplied explicitly
	conn, err := snet.DialSCION("udp4", &local, &remote)
	if err != nil {
		log.Fatal("Error: unable to dial", err)
	}
	fmt.Printf("Connected to %v.\n", &remote)

	b := make([]byte, 1<<12)
	for i := 0; i < *count || *count == 0; i++ {
		before := time.Now()

		// Send echo request to destination
		written, err := conn.Write([]byte(ReqMsg))
		if err != nil {
			log.Fatal("Error: unable to write", err)
		}
		if written != len(ReqMsg) {
			log.Fatal("Error: wrote incomplete message")
		}

		// Receive echo reply with timeout
		conn.SetDeadline(time.Now().Add(DefaultTimeout))
		read, err := conn.Read(b)
		conn.SetDeadline(time.Time{})
		if err != nil {
			log.Fatal("Error: unable to read", err)
		}
		if string(b[:read]) != ReplyMsg {
			fmt.Println("Received bad message", "expected", ReplyMsg,
				"actual", string(b[:read]))
		}
		after := time.Now()

		elapsed := after.Sub(before)
		fmt.Printf("%d bytes from %v: seq=%d time=%s\n", read, &remote, i, elapsed)

		time.Sleep((*interval) - elapsed)
	}
}

// Server listens on a SCION address and replies to any echo request messages.
// On any error, the server exits.
func Server() {
	// Initialize default SCION networking context
	err := snet.Init(local.IA, *sciond, *dispatcher)
	if err != nil {
		log.Fatal("Error: unable to initialize SCION network")
	}
	fmt.Println("SCION network successfully initialized.")

	// Listen on SCION address
	conn, err := snet.ListenSCION("udp4", &local)
	if err != nil {
		log.Fatal("Error: unable to listen", err)
	}
	fmt.Printf("Listening to %v.\n", &local)

	b := make([]byte, 1<<12)
	for i := 0; i < *count || *count == 0; i++ {
		// Receive echo request
		read, senderAddr, err := conn.ReadFrom(b)
		if err != nil {
			log.Fatal("Error: unable to read", err)
		}
		if string(b[:read]) != ReqMsg {
			fmt.Println("Received bad message", "expected", ReqMsg,
				"actual", string(b[:read]))
		}

		// Send echo reply
		written, err := conn.WriteTo([]byte(ReplyMsg), senderAddr)
		if err != nil {
			log.Fatal("Error: unable to write", err)
		}
		if written != len(ReplyMsg) {
			log.Fatal("Error: wrote incomplete message")
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
