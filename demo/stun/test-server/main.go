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

	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Print("Server running")

	var localAddr snet.UDPAddr
	flag.Var(&localAddr, "local", "Local address")
	flag.Parse()

	conn, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		log.Fatalf("Failed to listen on UDP connection: %v", err)
	}
	defer conn.Close()

	for {
		var pkt snet.Packet
		pkt.Prepare()

		n, lastHop, err := conn.ReadFrom(pkt.Bytes)
		if err != nil {
			log.Printf("Failed to read packet: %v", err)
			continue
		}
		pkt.Bytes = pkt.Bytes[:n]

		err = pkt.Decode()
		if err != nil {
			log.Printf("Failed to decode packet: %v", err)
			continue
		}

		pld, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			log.Print("Failed to read packet payload")
			continue
		}

		if int(pld.DstPort) == localAddr.Host.Port {
			log.Printf("Received data: \"%v\"", string(pld.Payload))

			pkt.Destination, pkt.Source = pkt.Source, pkt.Destination

			rp, ok := pkt.Path.(snet.RawPath)
			if !ok {
				log.Printf("Failed to reverse path, unexpected path type: %v", pkt.Path)
				continue
			}
			replyPather := snet.DefaultReplyPather{}
			replyPath, err := replyPather.ReplyPath(rp)
			if err != nil {
				log.Printf("Failed to reverse path: %v", err)
				continue
			}
			pkt.Path = replyPath

			pkt.Payload = snet.UDPPayload{
				SrcPort: pld.DstPort,
				DstPort: pld.SrcPort,
				Payload: pld.Payload,
			}

			err = pkt.Serialize()
			if err != nil {
				log.Printf("Failed to serialize SCION packet: %v", err)
				continue
			}

			_, err = conn.WriteTo(pkt.Bytes, lastHop)
			if err != nil {
				log.Printf("Failed to write packet: %v", err)
				continue
			}
		}
	}
}
