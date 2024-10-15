package main

import (
	"flag"
	"log"
	"net"

	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	var localAddr snet.UDPAddr
	flag.Var(&localAddr, "local", "Local address")
	flag.Parse()

	conn, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		log.Fatal("Failed to listen on UDP connection: %v\n", err)
	}
	defer conn.Close()

	for {
		var pkt snet.Packet
		pkt.Prepare()

		n, lastHop, err := conn.ReadFrom(pkt.Bytes)
		if err != nil {
			log.Printf("Failed to read packet: %v\n", err)
			continue
		}
		pkt.Bytes = pkt.Bytes[:n]

		err = pkt.Decode()
		if err != nil {
			log.Printf("Failed to decode packet: %v\n", err)
			continue
		}

		pld, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			log.Printf("Failed to read packet payload\n")
			continue
		}

		if int(pld.DstPort) == localAddr.Host.Port {
			log.Printf("Received data: \"%v\"\n", string(pld.Payload))

			pkt.Destination, pkt.Source = pkt.Source, pkt.Destination

			rp, ok := pkt.Path.(snet.RawPath)
			if !ok {
				log.Printf("Failed to reverse path, unecpected path type: %v", pkt.Path)
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
				log.Printf("Failed to serialize SCION packet: %v\n", err)
				continue
			}

			_, err = conn.WriteTo(pkt.Bytes, lastHop)
			if err != nil {
				log.Printf("Failed to write packet: %v\n", err)
				continue
			}
		}
	}
}
