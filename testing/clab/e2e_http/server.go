// Copyright 2026 Anapaya Systems
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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

func serverCmd() *cobra.Command {
	var (
		sciond   string
		listen   string
		duration time.Duration
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run an HTTP/3 server over SCION",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServer(context.Background(), sciond, listen, duration)
		},
	}
	cmd.Flags().StringVar(&sciond, "sciond", "127.0.0.1:30255", "SCION daemon address")
	cmd.Flags().StringVar(&listen, "listen", "", "underlay address to listen on (host:port, required)")
	cmd.Flags().DurationVar(&duration, "duration", 0, "shut down after this duration (0 = run forever)")
	cmd.MarkFlagRequired("listen")
	return cmd
}

func runServer(ctx context.Context, sciond, listen string, duration time.Duration) error {
	_, topo, err := dialDaemon(ctx, sciond)
	if err != nil {
		return err
	}
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return serrors.Wrap("resolving listen address", err, "listen", listen)
	}
	network := &snet.SCIONNetwork{Topology: topo, SCMPHandler: ignoreSCMP{}}
	conn, err := network.Listen(ctx, "udp", laddr)
	if err != nil {
		return serrors.Wrap("listening on SCION", err)
	}

	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	srv := &http3.Server{
		Handler: handler(topo.LocalIA.String()),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{alpn},
		},
		QUICConfig: quicConfig(),
	}

	if duration > 0 {
		go func() {
			t := time.NewTimer(duration)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
			_ = conn.Close()
		}()
	}

	fmt.Printf("serving HTTP/3 over SCION on %s (%s)\n", listen, topo.LocalIA)
	err = srv.Serve(conn)
	// A clean shutdown (conn closed after the duration) is not an error.
	if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// handler returns an HTTP handler that echoes the server's ISD-AS, so the
// client can confirm it reached the intended AS.
func handler(ia string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "e2e_http ok from %s\n", ia)
	})
	return mux
}
