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
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"

	"tailscale.com/net/stun"
)

// This demo handles all STUN requests manually to demonstrate how STUN can be implemented in SCION.
// Normal clients should use a client library that performs STUN automatically and transparently.

func main() {
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

	log.Printf("Available paths to %v:", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("\t%v", p)
	}

	sp := ps[0]

	log.Printf("Selected path to %v:", remoteAddr.IA)
	log.Printf("\t%v", sp)

	conn, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		log.Fatalf("Failed to bind UDP connection: %v", err)
	}
	defer conn.Close()

	var srcAddr netip.Addr
	var srcPort uint16
	var ok bool

	nextHop := sp.UnderlayNextHop()
	if nextHop == nil && remoteAddr.IA.Equal(localAddr.IA) {
		srcAddr, ok = netip.AddrFromSlice(localAddr.Host.IP)
		if !ok {
			log.Fatalf("Unexpected source address type")
		}

		// No STUN needed in intra-AS case
		srcAddr = srcAddr.Unmap()
		srcPort = uint16(localAddr.Host.Port)
		nextHop = remoteAddr.Host
	} else {

		// Generate and send STUN request
		txID := stun.NewTxID()
		req := stun.Request(txID)

		var stunAddr = *nextHop
		stunAddr.Port = 30042

		_, err = conn.WriteToUDP(req, &stunAddr)
		if err != nil {
			log.Fatalf("Failed to write STUN packet: %v", err)
		}

		log.Print("Sent STUN request")

		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			log.Fatalf("Failed to read STUN packet: %v", err)
		}

		// Read STUN response
		tid, stunResp, err := stun.ParseResponse(buf[:n])
		if err != nil {
			log.Fatalf("Failed to decode STUN packet: %v", err)
		}
		if tid != txID {
			log.Fatalf("txid mismatch: got %v, want %v", tid, txID)
		}

		log.Printf("Received STUN response: %v", stunResp)

		// Use address and port from STUN response as source address and port
		srcAddr = stunResp.Addr()
		srcPort = stunResp.Port()
	}

	// Continue with normal SCION communication

	dstAddr, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		log.Fatal("Unexpected destination address type")
	}
	dstAddr = dstAddr.Unmap()

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localAddr.IA,
				Host: addr.HostIP(srcAddr),
			},
			Destination: snet.SCIONAddress{
				IA:   remoteAddr.IA,
				Host: addr.HostIP(dstAddr),
			},
			Path: sp.Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: uint16(remoteAddr.Host.Port),
				Payload: []byte(data),
			},
		},
	}

	err = pkt.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize SCION packet: %v", err)
	}

	_, err = conn.WriteTo(pkt.Bytes, nextHop)
	if err != nil {
		log.Fatalf("Failed to write SCION packet: %v", err)
	}

	pkt.Prepare()
	n, _, err := conn.ReadFrom(pkt.Bytes)
	if err != nil {
		log.Fatalf("Failed to read SCION packet: %v", err)
	}
	pkt.Bytes = pkt.Bytes[:n]

	err = pkt.Decode()
	if err != nil {
		log.Fatalf("Failed to decode SCION packet: %v", err)
	}

	pld, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		log.Fatal("Failed to read packet payload")
	}

	log.Printf("Received data: \"%s\"", string(pld.Payload))
}
