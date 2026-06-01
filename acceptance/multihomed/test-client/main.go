// Copyright 2026 ETH Zurich
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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/scionproto/scion/pkg/daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("test-client starting")

	// Parse test inputs. The remote is provided as a full SCION UDP address so the same
	// client binary can probe server primary and secondary IPs without code changes.
	var daemonAddr string
	var localAddr snet.UDPAddr
	var remoteAddr snet.UDPAddr
	var expect string
	var expectAddr *snet.UDPAddr

	flag.StringVar(&daemonAddr, "daemon", "", "SCION daemon address")
	flag.Var(&localAddr, "local", "Local SCION address")
	flag.Var(&remoteAddr, "remote", "Remote SCION address")
	flag.StringVar(&expect, "expect", "", "Expected remote SCION address")
	flag.Parse()
	log.Printf("parsed args daemon=%q local=%q remote=%q expect=%q",
		daemonAddr, localAddr.String(), remoteAddr.String(), expect)
	log.Printf("local address. IA=%s, IP=%s, port=%d",
		localAddr.IA,
		localAddr.Host.IP,
		localAddr.Host.Port,
	)

	if expect != "" {
		parsed, err := snet.ParseUDPAddr(expect)
		if err != nil {
			log.Fatalf("parse expected remote address: %v", err)
		}
		expectAddr = parsed
	}

	if daemonAddr == "" {
		daemonAddr = os.Getenv("SCION_DAEMON_ADDRESS")
	}
	if daemonAddr == "" {
		daemonAddr = os.Getenv("SCION_DAEMON")
	}
	if daemonAddr == "" {
		log.Fatal("daemon address missing: pass -daemon or set SCION_DAEMON_ADDRESS/SCION_DAEMON")
	}
	log.Printf("using daemon address %s", daemonAddr)

	// Resolve a path from local IA to remote IA.
	ctx := context.Background()
	sd, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		log.Fatalf("connect daemon: %v", err)
	}
	defer sd.Close()
	log.Printf("connected to daemon")

	paths, err := sd.Paths(ctx, remoteAddr.IA, localAddr.IA,
		daemontypes.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalf("path lookup: %v", err)
	}
	if len(paths) == 0 {
		log.Fatalf("no path from %s to %s", localAddr.IA, remoteAddr.IA)
	}
	sp := paths[0]
	log.Printf("path lookup returned %d paths; using first path", len(paths))

	// Build a SCION connection pinned to the selected path.
	topo, err := daemon.LoadTopology(ctx, sd)
	if err != nil {
		log.Fatalf("load topology: %v", err)
	}
	remoteAddr.Path = sp.Dataplane()
	remoteAddr.NextHop = sp.UnderlayNextHop()

	sn := snet.SCIONNetwork{
		Topology: topo,
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sd},
		},
	}

	conn, err := sn.Dial(ctx, "udp", localAddr.Host, &remoteAddr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("dial successful: local_host=%s remote=%s", localAddr.Host, remoteAddr.String())

	// Exchange ping/pong payloads and assert reply endpoint if requested by the caller.
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		log.Fatalf("write ping: %v", err)
	}
	log.Printf("ping sent")

	buf := make([]byte, 2048)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("read pong: %v", err)
	}
	log.Printf("received response from %s (%d bytes)", from, n)
	if string(buf[:n]) != "pong" {
		log.Fatalf("unexpected payload: %q", string(buf[:n]))
	}
	if expectAddr != nil {
		got, ok := from.(*snet.UDPAddr)
		if !ok {
			log.Fatalf("unexpected remote type %T", from)
		}
		if got.IA != expectAddr.IA || got.Host.Port != expectAddr.Host.Port ||
			!got.Host.IP.Equal(expectAddr.Host.IP) {
			log.Fatalf("unexpected remote. got=%s want=%s", got, expectAddr)
		}
	}

	log.Printf("client success remote=%s", from)
	fmt.Printf("test-client done\n")
}
