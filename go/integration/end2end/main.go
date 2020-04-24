// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	ping = "ping:"
	pong = "pong:"
)

var (
	remote  snet.UDPAddr
	timeout = &util.DurWrap{Duration: 10 * time.Second}
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()
	addFlags()
	integration.Setup()
	validateFlags()

	closeTracer, err := integration.InitTracer("end_2_end")
	if err != nil {
		log.Crit("Unable to create tracer", "err", err)
		return 1
	}
	defer closeTracer()
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	return client{}.run()
}

func addFlags() {
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
}

func validateFlags() {
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.Port == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.Port)
		}
		if timeout.Duration == 0 {
			integration.LogFatal("Invalid timeout provided", "timeout", timeout)
		}
	}
}

type server struct {
}

func (s server) run() {
	log.Info("Starting server", "ia", integration.Local.IA)
	defer log.Info("Finished server", "ia", integration.Local.IA)

	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.NewSCMPHandler(
			sciond.RevHandler{Connector: integration.SDConn()},
		),
	}
	conn, port, err := connFactory.Register(context.Background(), integration.Local.IA,
		integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", port)
		fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
	}
	log.Debug("Listening", "local", fmt.Sprintf("%v:%d", integration.Local.Host, port))
	// Receive ping message
	for {
		var p snet.Packet
		var ov net.UDPAddr
		if err := conn.ReadFrom(&p, &ov); err != nil {
			log.Error("Error reading packet", "err", err)
			continue
		}
		if string(p.Payload.(common.RawBytes)) != ping+integration.Local.IA.String() {
			integration.LogFatal("Received unexpected data", "data", p.Payload.(common.RawBytes))
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
		// Send pong

		if p.Path != nil {
			if err := p.Path.Reverse(); err != nil {
				log.Debug(fmt.Sprintf("Error reversing path, err = %v", err))
				continue
			}
		}
		p.Destination, p.Source = p.Source, p.Destination
		p.L4Header.Reverse()
		p.Payload = common.RawBytes(pongMessage(integration.Local.IA, p.Destination.IA))
		if err := conn.WriteTo(&p, &ov); err != nil {
			integration.LogFatal("Unable to send reply", "err", err)
		}
		log.Info("Sent pong to", "client", p.Destination)
	}
}

type client struct {
	conn   snet.PacketConn
	port   uint16
	sdConn sciond.Connector
}

func (c client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	log.Info("Starting", "pair", pair)
	defer log.Info("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.NewSCMPHandler(
			sciond.RevHandler{Connector: integration.SDConn()},
		),
	}

	var err error
	c.conn, c.port, err = connFactory.Register(context.Background(), integration.Local.IA,
		integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local",
		fmt.Sprintf("%v,[%v]:%d", integration.Local.IA, integration.Local.Host.IP, c.port))
	c.sdConn = integration.SDConn()
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "run")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	// Send ping
	if err := c.ping(ctx, n); err != nil {
		logger.Error("Could not send packet", "err", err)
		ext.Error.Set(span, true)
		return false
	}
	// Receive pong
	if err := c.pong(ctx); err != nil {
		logger.Debug("Error receiving pong", "err", err)
		ext.Error.Set(span, true)
		return false
	}
	return true
}

func (c client) ping(ctx context.Context, n int) error {
	if err := c.getRemote(ctx, n); err != nil {
		return err
	}
	c.conn.SetWriteDeadline(getDeadline(ctx))
	if remote.NextHop == nil {
		remote.NextHop = &net.UDPAddr{
			IP:   remote.Host.IP,
			Port: topology.EndhostPort,
		}
	}
	var debugID [common.ExtnFirstLineLen]byte
	// API guarantees return values are ok
	_, _ = rand.Read(debugID[:])
	return c.conn.WriteTo(
		&snet.Packet{
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: addr.HostFromIP(remote.Host.IP),
				},
				Source: snet.SCIONAddress{
					IA:   integration.Local.IA,
					Host: addr.HostFromIP(integration.Local.Host.IP),
				},
				Path: remote.Path,
				Extensions: []common.Extension{
					layers.ExtnE2EDebug{
						ID: debugID,
					},
				},
				L4Header: &l4.UDP{
					SrcPort: c.port,
					DstPort: uint16(remote.Host.Port),
				},
				Payload: common.RawBytes(
					pingMessage(remote.IA),
				),
			},
		},
		remote.NextHop,
	)
}

func (c client) getRemote(ctx context.Context, n int) error {
	if remote.IA.Equal(integration.Local.IA) {
		return nil
	}
	// Get paths from sciond
	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		sciond.PathReqFlags{Refresh: n != 0, PathCount: 1})
	if err != nil {
		return common.NewBasicError("Error requesting paths", err)
	}
	if len(paths) == 0 {
		return serrors.New("No path entries found")
	}
	path := paths[0]
	// Extract forwarding path from sciond response
	remote.Path = path.Path()
	remote.NextHop = path.UnderlayNextHop()
	return nil
}

func (c client) pong(ctx context.Context) error {
	c.conn.SetReadDeadline(getDeadline(ctx))
	var p snet.Packet
	var ov net.UDPAddr
	if err := c.conn.ReadFrom(&p, &ov); err != nil {
		return common.NewBasicError("Error reading packet", err)
	}
	expected := pong + remote.IA.String() + integration.Local.IA.String()
	if string(p.Payload.(common.RawBytes)) != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			string(p.Payload.(common.RawBytes)), "expected", expected)
	}
	log.Info("Received pong", "server", p.Source)
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	dl, ok := ctx.Deadline()
	if !ok {
		integration.LogFatal("No deadline in context")
	}
	return dl
}

func pingMessage(server addr.IA) []byte {
	return []byte(ping + server.String())
}

func pongMessage(server, client addr.IA) []byte {
	return []byte(pong + server.String() + client.String())
}
