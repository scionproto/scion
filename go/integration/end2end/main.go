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
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	c := client{}
	return c.run()
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
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: sciond.RevHandler{Connector: integration.SDConn()},
		},
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
		udp, ok := p.Payload.(snet.UDPPayload)
		if !ok {
			log.Error("Unexpected payload received", "type", common.TypeOf(p.Payload))
			continue
		}
		pld := string(udp.Payload)

		p.Destination, p.Source = p.Source, p.Destination
		p.Payload = snet.UDPPayload{
			DstPort: udp.SrcPort,
			SrcPort: udp.DstPort,
			Payload: pongMessage(integration.Local.IA, p.Destination.IA),
		}
		if pld != ping+integration.Local.IA.String() {
			integration.LogFatal("Received unexpected data", "data", pld)
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
		// reverse path
		if err := p.Path.Reverse(); err != nil {
			log.Debug(fmt.Sprintf("Error reversing path, err = %v", err))
			continue
		}
		// Send pong
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

	errorPaths map[snet.PathFingerprint]struct{}
}

func (c *client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	log.Info("Starting", "pair", pair)
	defer log.Info("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: sciond.RevHandler{Connector: integration.SDConn()},
		},
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
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "run")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	// Send ping
	path, err := c.ping(ctx, n)
	if err != nil {
		logger.Error("Could not send packet", "err", err)
		ext.Error.Set(span, true)
		return false
	}
	// Receive pong
	if err := c.pong(ctx); err != nil {
		logger.Debug("Error receiving pong", "err", err)
		ext.Error.Set(span, true)
		if path != nil {
			c.errorPaths[snet.Fingerprint(path)] = struct{}{}
		}
		return false
	}
	return true
}

func (c *client) ping(ctx context.Context, n int) (snet.Path, error) {
	path, err := c.getRemote(ctx, n)
	if err != nil {
		return nil, err
	}
	c.conn.SetWriteDeadline(getDeadline(ctx))
	if remote.NextHop == nil {
		remote.NextHop = &net.UDPAddr{
			IP:   remote.Host.IP,
			Port: topology.EndhostPort,
		}
	}
	pkt := &snet.Packet{
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
			Payload: snet.UDPPayload{
				SrcPort: c.port,
				DstPort: uint16(remote.Host.Port),
				Payload: pingMessage(remote.IA),
			},
		},
	}
	log.Debug("sending ping", "attempt", n, "path", path)
	return path, c.conn.WriteTo(pkt, remote.NextHop)
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		return nil, nil
	}
	// Get paths from sciond
	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		sciond.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, common.NewBasicError("Error requesting paths", err)
	}
	// if all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	// select first path that didn't error before.
	var path snet.Path
	for _, p := range paths {
		if _, ok := c.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		path = p
		break
	}
	if path == nil {
		return nil, serrors.New("no path found",
			"candidates", len(paths), "errors", len(c.errorPaths))
	}
	// Extract forwarding path from sciond response
	remote.Path = path.Path()
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) pong(ctx context.Context) error {
	c.conn.SetReadDeadline(getDeadline(ctx))
	var p snet.Packet
	var ov net.UDPAddr
	if err := c.conn.ReadFrom(&p, &ov); err != nil {
		return common.NewBasicError("Error reading packet", err)
	}
	expected := pong + remote.IA.String() + integration.Local.IA.String()
	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received", "type", common.TypeOf(p.Payload))
	}
	pld := string(udp.Payload)
	if pld != expected {
		return serrors.New("unexpected data received",
			"data", pld, "expected", expected)
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
