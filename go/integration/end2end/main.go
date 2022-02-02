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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/daemon"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/metrics"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	ping = "ping"
	pong = "pong"
)

type Ping struct {
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

type Pong struct {
	Client  addr.IA `json:"client"`
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

var (
	remote                 snet.UDPAddr
	timeout                = &util.DurWrap{Duration: 10 * time.Second}
	scionPacketConnMetrics = metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter      = scionPacketConnMetrics.SCMPErrors
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

	closeTracer, err := integration.InitTracer("end2end-" + integration.Mode)
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

type server struct{}

func (s server) run() {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: integration.SDConn()},
			SCMPErrors:        scmpErrorsCounter,
		},
		SCIONPacketConnMetrics: scionPacketConnMetrics,
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
	log.Info("Listening", "local", fmt.Sprintf("%v:%d", integration.Local.Host, port))

	// Receive ping message
	for {
		if err := s.handlePing(conn); err != nil {
			log.Error("Error handling ping", "err", err)
		}
	}
}

func (s server) handlePing(conn snet.PacketConn) error {
	var p snet.Packet
	var ov net.UDPAddr
	if err := readFrom(conn, &p, &ov); err != nil {
		return serrors.WrapStr("reading packet", err)
	}
	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Ping
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.New("invalid payload contents",
			"source", p.Source,
			"destination", p.Destination,
			"data", string(udp.Payload),
		)
	}

	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.WrapStr("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		))
	}
	log.Info(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
	raw, err := json.Marshal(Pong{
		Client:  p.Source.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.WrapStr("packing pong", err))
	}

	p.Destination, p.Source = p.Source, p.Destination
	p.Payload = snet.UDPPayload{
		DstPort: udp.SrcPort,
		SrcPort: udp.DstPort,
		Payload: raw,
	}
	// reverse path
	rpath, ok := p.Path.(snet.RawPath)
	if !ok {
		return serrors.New("unecpected path", "type", common.TypeOf(p.Path))
	}
	replypather := snet.DefaultReplyPather{}
	replyPath, err := replypather.ReplyPath(rpath)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	p.Path = replyPath
	// Send pong
	if err := conn.WriteTo(&p, &ov); err != nil {
		return withTag(serrors.WrapStr("sending reply", err))
	}
	log.Info("Sent pong to", "client", p.Destination)
	return nil
}

type client struct {
	conn   snet.PacketConn
	port   uint16
	sdConn daemon.Connector

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
			RevocationHandler: daemon.RevHandler{Connector: integration.SDConn()},
			SCMPErrors:        scmpErrorsCounter,
		},
		SCIONPacketConnMetrics: scionPacketConnMetrics,
	}

	var err error
	c.conn, c.port, err = connFactory.Register(context.Background(), integration.Local.IA,
		integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Info("Send on", "local",
		fmt.Sprintf("%v,[%v]:%d", integration.Local.IA, integration.Local.Host.IP, c.port))
	c.sdConn = integration.SDConn()
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "attempt")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}
	span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
	defer span.Finish()

	// Send ping
	if err := c.ping(ctx, n, path); err != nil {
		tracing.Error(span, err)
		logger.Error("Could not send packet", "err", err)
		return false
	}
	// Receive pong
	if err := c.pong(ctx); err != nil {
		tracing.Error(span, err)
		logger.Error("Error receiving pong", "err", err)
		if path != nil {
			c.errorPaths[snet.Fingerprint(path)] = struct{}{}
		}
		return false
	}
	return true
}

func (c *client) ping(ctx context.Context, n int, path snet.Path) error {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
	if err != nil {
		return serrors.WrapStr("packing ping", err)
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
				Payload: rawPing,
			},
		},
	}
	log.Info("sending ping", "attempt", n, "path", path)
	if err := c.conn.WriteTo(pkt, remote.NextHop); err != nil {
		return err
	}
	return nil
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	span, ctx := tracing.StartSpanFromCtx(ctx, "attempt.get_remote")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemon.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, withTag(serrors.WrapStr("requesting paths", err))
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
		return nil, withTag(serrors.New("no path found",
			"candidates", len(paths),
			"errors", len(c.errorPaths),
		))
	}
	// Extract forwarding path from the SCION Daemon response
	remote.Path = path.Dataplane()
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) pong(ctx context.Context) error {
	c.conn.SetReadDeadline(getDeadline(ctx))
	var p snet.Packet
	var ov net.UDPAddr
	if err := readFrom(c.conn, &p, &ov); err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received", "type", common.TypeOf(p.Payload))
	}

	var pld Pong
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.WrapStr("unpacking pong", err, "data", string(udp.Payload))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
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

func readFrom(conn snet.PacketConn, pkt *snet.Packet, ov *net.UDPAddr) error {
	err := conn.ReadFrom(pkt, ov)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return err
	}
	return serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}
