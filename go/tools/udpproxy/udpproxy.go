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
	listen = flag.String("listen", "", "address to listen on (e.g., 127.0.0.1:30041) (required)")
	to     = flag.String("to", "", "address to redirect to (e.g., 127.0.0.1:30041) (required)")
)

func main() {
	flag.Parse()

	if err := Proxy(*listen, *to); err != nil {
		log.Crit("Fatal proxy error", "err", err)
		os.Exit(1)
	}
}

func Proxy(listen, to string) error {
	listenAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return serrors.New("unable to parse listen address", "err", err)
	}

	listenConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return serrors.New("unable to open listen conn", "err", err)
	}

	redirectConn, err := net.Dial("udp", to)
	if err != nil {
		return serrors.New("unable to open conn to destination", "err", err)
	}
	log.Info(
		fmt.Sprintf(
			"Redirecting messages received on %v to %v",
			listenConn.LocalAddr(),
			redirectConn.RemoteAddr(),
		),
	)

	b := make([]byte, 1<<16)
	for {
		n, _, err := listenConn.ReadFromUDP(b)
		if err != nil {
			return serrors.New("unable to read from listen conn", "err", err)
		}

		_, err = redirectConn.Write(b[:n])
		if err != nil {
			return serrors.New("unable to write to destination", "err", err)
		}
	}
}
