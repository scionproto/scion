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
	localX = flag.String("local_x", "",
		"local UDP address on network x, in IP:port format  (required)")
	remoteX = flag.String("remote_x", "",
		"remote UDP address on network x, in IP:port format (required)")
	localY = flag.String("local_y", "",
		"local UDP address on network y, in IP:port format (required)")
	remoteY = flag.String("remote_y", "",
		"remote UDP address on network y, in IP:port format (required)")
)

func main() {
	flag.Parse()

	if err := Proxy(*localX, *remoteX, *localY, *remoteY); err != nil {
		log.Error("Fatal proxy error", "err", err)
		os.Exit(1)
	}
}

func Proxy(localX, remoteX, localY, remoteY string) error {
	lxAddr, err := net.ResolveUDPAddr("udp", localX)
	if err != nil {
		return serrors.New("unable to parse local x address", "err", err)
	}
	rxAddr, err := net.ResolveUDPAddr("udp", remoteX)
	if err != nil {
		return serrors.New("unable to parse remote x address", "err", err)
	}
	xConn, err := net.ListenUDP("udp", lxAddr)
	if err != nil {
		return serrors.New("unable to open x conn", "err", err)
	}

	lyAddr, err := net.ResolveUDPAddr("udp", localY)
	if err != nil {
		return serrors.New("unable to parse local y address", "err", err)
	}
	ryAddr, err := net.ResolveUDPAddr("udp", remoteY)
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
			remoteY,
		),
	)
	log.Info(
		fmt.Sprintf(
			"Redirecting messages received on %v to %v",
			yConn.LocalAddr(),
			remoteX,
		),
	)

	go func() {
		defer log.HandlePanic()
		redirect(xConn, yConn, ryAddr)
	}()
	go func() {
		defer log.HandlePanic()
		redirect(yConn, xConn, rxAddr)
	}()
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
