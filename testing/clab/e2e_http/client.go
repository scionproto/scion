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
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app/path"
)

func clientCmd() *cobra.Command {
	var (
		sciond  string
		remote  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Fetch a URL from an HTTP/3-over-SCION server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			body, err := runClient(ctx, sciond, remote)
			if err != nil {
				return err
			}
			fmt.Print(body)
			return nil
		},
	}
	cmd.Flags().StringVar(&sciond, "sciond", "127.0.0.1:30255", "SCION daemon address")
	cmd.Flags().StringVar(&remote, "remote", "",
		"server SCION UDP address (ISD-AS,host:port, required)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "overall request timeout")
	cmd.MarkFlagRequired("remote")
	return cmd
}

func runClient(ctx context.Context, sciond, remoteStr string) (string, error) {
	conn, topo, err := dialDaemon(ctx, sciond)
	if err != nil {
		return "", err
	}
	remote, err := snet.ParseUDPAddr(remoteStr)
	if err != nil {
		return "", serrors.Wrap("parsing remote address", err, "remote", remoteStr)
	}

	// Resolve a path to the destination AS and attach it to the remote address.
	p, err := path.Choose(ctx, conn, remote.IA)
	if err != nil {
		return "", serrors.Wrap("choosing path", err)
	}
	remote.Path = p.Dataplane()
	remote.NextHop = p.UnderlayNextHop()

	// Pick the local underlay IP that routes towards the next hop (or the
	// destination host for AS-internal paths).
	target := remote.Host.IP
	if remote.NextHop != nil {
		target = remote.NextHop.IP
	}
	localIP, err := addrutil.ResolveLocal(target)
	if err != nil {
		return "", serrors.Wrap("resolving local address", err)
	}

	network := &snet.SCIONNetwork{Topology: topo, SCMPHandler: ignoreSCMP{}}
	pconn, err := network.Listen(ctx, "udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		return "", serrors.Wrap("opening local SCION socket", err)
	}
	tr := &quic.Transport{Conn: pconn}
	defer tr.Close()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // test certificate; no PKI for the data plane
			NextProtos:         []string{alpn},
			ServerName:         "e2e-http",
		},
		QUICConfig: quicConfig(),
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return tr.Dial(ctx, remote, tlsCfg, cfg)
		},
	}
	defer rt.Close()

	client := &http.Client{Transport: rt}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://e2e-http/", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", serrors.Wrap("HTTP/3 request", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", serrors.Wrap("reading response body", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", serrors.New("unexpected status", "status", resp.Status, "body", string(body))
	}
	return string(body), nil
}
