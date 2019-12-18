// Copyright 2019 Anapaya Systems

package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	lx = flag.String("lx", "", "address to listen on network x (e.g., 127.0.0.1:30041) (required)")
	rx = flag.String("rx", "", "address to send to on network x (required)")
	ly = flag.String("ly", "", "address to listen on network y (e.g., 127.0.0.1:30041) (required)")
	ry = flag.String("ry", "", "address to send to on network y (required)")
)

func main() {
	flag.Parse()

	if err := Proxy(*lx, *rx, *ly, *ry); err != nil {
		log.Crit("Fatal proxy error", "err", err)
		os.Exit(1)
	}
}

func Proxy(lx, rx, ly, ry string) error {
	lxAddr, err := net.ResolveUDPAddr("udp", lx)
	if err != nil {
		return serrors.New("unable to parse local x address", "err", err)
	}
	rxAddr, err := net.ResolveUDPAddr("udp", rx)
	if err != nil {
		return serrors.New("unable to parse remote x address", "err", err)
	}
	xConn, err := net.ListenUDP("udp", lxAddr)
	if err != nil {
		return serrors.New("unable to open x conn", "err", err)
	}

	lyAddr, err := net.ResolveUDPAddr("udp", ly)
	if err != nil {
		return serrors.New("unable to parse local y address", "err", err)
	}
	ryAddr, err := net.ResolveUDPAddr("udp", ry)
	if err != nil {
		return serrors.New("unable to parse remote y address", "err", err)
	}
	yConn, err := net.ListenUDP("udp", lyAddr)
	if err != nil {
		return serrors.New("unable to open y conn", "err", err)
	}

	log.Info(
		fmt.Sprintf(
			"Redirecting messages received on %v to %v",
			xConn.LocalAddr(),
			ry,
		),
	)
	log.Info(
		fmt.Sprintf(
			"Redirecting messages received on %v to %v",
			yConn.LocalAddr(),
			rx,
		),
	)

	go redirect(xConn, yConn, ryAddr)
	go redirect(yConn, xConn, rxAddr)
	select {}
}

func redirect(from, to net.PacketConn, toAddr *net.UDPAddr) {
	b := make([]byte, 1<<16)
	for {
		n, _, err := from.ReadFrom(b)
		if err != nil {
			log.Error("Unable to read from listen conn", "err", err)
		}

		_, err = to.WriteTo(b[:n], toAddr)
		if err != nil {
			log.Error("unable to write to destination", "err", err)
		}
	}
}
