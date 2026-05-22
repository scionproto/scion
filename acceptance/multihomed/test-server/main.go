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
	"net"
	"os"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	log.SetOutput(os.Stdout)

	// Parse test inputs. The same server binary is used for:
	// - bound mode: bind to a specific host IP
	// - multihomed mode: bind to 0.0.0.0 and accept traffic via multiple local IPs
	var daemonAddr string
	var bindAddr string
	var port int
	var mode string

	flag.StringVar(&daemonAddr, "daemon", "", "SCION daemon address")
	flag.StringVar(&bindAddr, "bind", "0.0.0.0", "Bind host")
	flag.IntVar(&port, "port", 31000, "Bind UDP port")
	flag.StringVar(&mode, "mode", "multihomed", "Server mode")
	flag.Parse()

	if daemonAddr == "" {
		daemonAddr = os.Getenv("SCION_DAEMON_ADDRESS")
	}
	if daemonAddr == "" {
		daemonAddr = os.Getenv("SCION_DAEMON")
	}
	if daemonAddr == "" {
		log.Fatal("daemon address missing: pass -daemon or set SCION_DAEMON_ADDRESS/SCION_DAEMON")
	}

	// Initialize SCION networking stack from daemon topology.
	ctx := context.Background()
	sd, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		log.Fatalf("connect daemon: %v", err)
	}
	defer sd.Close()

	topo, err := daemon.LoadTopology(ctx, sd)
	if err != nil {
		log.Fatalf("load topology: %v", err)
	}

	sn := snet.SCIONNetwork{
		Topology: topo,
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sd},
		},
	}

	// Bind listening socket according to requested mode/host.
	local, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindAddr, fmt.Sprintf("%d", port)))
	if err != nil {
		log.Fatalf("parse bind address: %v", err)
	}
	conn, err := sn.Listen(ctx, "udp", local)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("server running mode=%s daemon=%s bind=%s:%d", mode, daemonAddr, bindAddr, port)

	// Single ping/pong exchange; process exits afterwards so the test can restart with a fresh bind.
	buf := make([]byte, 2048)
	n, remote, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("read ping: %v", err)
	}
	if string(buf[:n]) != "ping" {
		log.Fatalf("unexpected payload: %q", string(buf[:n]))
	}

	_, err = conn.WriteTo([]byte("pong"), remote)
	if err != nil {
		log.Fatalf("write pong: %v", err)
	}

	log.Printf("served ping from %s", remote)
}
