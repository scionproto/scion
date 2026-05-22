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
	"flag"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	log.SetOutput(os.Stdout)

	// Parse test inputs. The same server binary is used for:
	// - IPv4 unbound mode: bind to 0.0.0.0
	// - IPv6 unbound mode: bind to ::
	var bindAddr string
	var port int

	flag.StringVar(&bindAddr, "bind", "0.0.0.0", "Bind host")
	flag.IntVar(&port, "port", 31000, "Bind UDP port")
	flag.Parse()

	// Bind a raw UDP socket in the tester namespace. Replies are created by reversing the
	// received SCION packet, which preserves the destination address the client originally used.
	local, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindAddr, portString(port)))
	if err != nil {
		log.Fatalf("parse bind address: %v", err)
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("server running bind=%s:%d", bindAddr, port)

	// Single ping/pong exchange; process exits afterwards so the test can restart with a fresh bind.
	var pkt snet.Packet
	pkt.Prepare()
	n, lastHop, err := conn.ReadFrom(pkt.Bytes)
	if err != nil {
		log.Fatalf("read ping: %v", err)
	}
	pkt.Bytes = pkt.Bytes[:n]

	if err := pkt.Decode(); err != nil {
		log.Fatalf("decode packet: %v", err)
	}
	pld, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		log.Fatalf("unexpected payload type %T", pkt.Payload)
	}
	if string(pld.Payload) != "ping" {
		log.Fatalf("unexpected payload: %q", string(pld.Payload))
	}

	rawPath, ok := pkt.Path.(snet.RawPath)
	if !ok {
		log.Fatalf("unexpected path type %T", pkt.Path)
	}
	replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rawPath)
	if err != nil {
		log.Fatalf("reverse path: %v", err)
	}

	pkt.Destination, pkt.Source = pkt.Source, pkt.Destination
	pkt.Path = replyPath
	pkt.Payload = snet.UDPPayload{
		SrcPort: pld.DstPort,
		DstPort: pld.SrcPort,
		Payload: []byte("pong"),
	}
	if err := pkt.Serialize(); err != nil {
		log.Fatalf("serialize reply: %v", err)
	}
	if _, err := conn.WriteTo(pkt.Bytes, lastHop); err != nil {
		log.Fatalf("write pong: %v", err)
	}

	log.Printf("served ping from %s", pkt.Destination)
}

func portString(port int) string {
	return strconv.Itoa(port)
}
