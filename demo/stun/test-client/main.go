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

	"github.com/scionproto/scion/demo/stun/test-client/stun"
)

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
		log.Fatal("Failed to create SCION daemon connector:", err)
	}

	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalf("Failed to lookup paths: %v:", err)
	}

	if len(ps) == 0 {
		log.Fatalf("No paths to %v available", remoteAddr.IA)
	}

	log.Printf("Available paths to %v:\n", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("\t%v\n", p)
	}

	sp := ps[0]

	log.Printf("Selected path to %v:\n", remoteAddr.IA)
	log.Printf("\t%v\n", sp)

	conn, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		log.Fatalf("Failed to bind UDP connection: %v\n", err)
	}
	defer conn.Close()

	var srcAddr netip.Addr
	var srcPort uint16
	var ok bool

	nextHop := sp.UnderlayNextHop()
	if nextHop == nil && remoteAddr.IA.Equal(localAddr.IA) {
		srcAddr, ok = netip.AddrFromSlice(localAddr.Host.IP)
		if !ok {
			log.Fatalf("Unexpected address type\n")
		}
		srcPort = uint16(localAddr.Host.Port)
		nextHop = remoteAddr.Host
	} else {
		txID := stun.NewTxID()
		req := stun.Request(txID)

		var stunAddr = *nextHop
		stunAddr.Port = 30042

		_, err = conn.WriteToUDP(req, &stunAddr)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("sent stun packet")

		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			log.Fatal(err)
		}

		tid, stunResp, err := stun.ParseResponse(buf[:n])
		if err != nil {
			log.Fatal(err)
		}
		if tid != txID {
			log.Fatalf("txid mismatch: got %v, want %v", tid, txID)
		}

		log.Printf("stun response: %v", stunResp)

		srcAddr = stunResp.Addr()
		srcPort = stunResp.Port()
	}

	dstAddr, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		log.Fatalf("Unexpected address type\n")
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
		log.Fatalf("Failed to serialize SCION packet: %v\n", err)
	}

	_, err = conn.WriteTo(pkt.Bytes, nextHop)
	if err != nil {
		log.Fatalf("Failed to write packet: %v\n", err)
	}

	pkt.Prepare()
	n, _, err := conn.ReadFrom(pkt.Bytes)
	if err != nil {
		log.Fatalf("Failed to read packet: %v\n", err)
	}
	pkt.Bytes = pkt.Bytes[:n]

	err = pkt.Decode()
	if err != nil {
		log.Fatalf("Failed to decode packet: %v\n", err)
	}

	pld, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		log.Fatalf("Failed to read packet payload\n")
	}

	log.Printf("Received data: \"%s\"", string(pld.Payload))
}
