// Copyright 2025 ETH Zurich
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
	"log"
	"os"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Client running")
	var daemonAddr string
	var localAddr snet.UDPAddr
	var remoteAddr snet.UDPAddr
	var data string
	flag.StringVar(&daemonAddr, "daemon", "127.0.0.1:30255", "Daemon address")
	flag.Var(&localAddr, "local", "Local address")
	flag.Var(&remoteAddr, "remote", "Remote address")
	flag.StringVar(&data, "data", "", "Data")
	flag.Parse()

	ctx := context.Background()

	dc, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to create SCION daemon connector: %v", err)
	}

	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalf("Failed to lookup paths: %v", err)
	}

	if len(ps) == 0 {
		log.Fatalf("No paths to %v available", remoteAddr.IA)
	}

	sp := ps[0]

	log.Printf("Selected path to %v:", remoteAddr.IA)
	log.Printf("\t%v", sp)

	topology, err := daemon.LoadTopology(ctx, dc)
	if err != nil {
		log.Fatalf("Failed to load topology from daemon: %v", err)
	}

	scionNetwork := snet.SCIONNetwork{
		Topology:    topology,
		STUNEnabled: true,
	}

	remoteAddr.Path = sp.Dataplane()
	remoteAddr.NextHop = sp.UnderlayNextHop()

	conn, err := scionNetwork.Dial(ctx, "udp", localAddr.Host, &remoteAddr)
	if err != nil {
		log.Fatalf("Failed to dial SCION address: %v", err)
	}

	defer conn.Close()

	log.Print("Successfully established SCION connection")

	_, err = conn.Write([]byte(data))
	if err != nil {
		log.Fatalf("Failed to write to SCION connection: %v", err)
	}

	log.Printf("Successfully sent data to %v", remoteAddr.IA)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read from SCION connection: %v", err)
	}

	response := string(buf[:n])
	log.Printf("Received data: \"%s\"", response)
	if response != data {
		log.Fatalf("Assertion failed: response does not match sent data")
	}
	os.Exit(0)
}
