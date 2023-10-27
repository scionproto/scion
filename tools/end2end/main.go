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

// This is a general purpose client/server code for end2end tests. It plays
// ping-pong with some variantions depending on command line arguments.
//
// One of the variants is for the client to send pings to the server
// until it receives at least one pong from the server or a given
// deadline was reached. The server responds to pings and the client
// wait for a response before doing anything else.
//
// Another variant is for the client to send back-to-back pings to the
// server until the sending fails or some deadline was reached. In this case
// the client isn't waiting for responses. The client checks at the end
// whether at least one response has been received.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/tracing"
	libint "github.com/scionproto/scion/tools/integration"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
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
	epic                   bool
	game                   string
	traces                 bool
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()
	addFlags()
	err := integration.Setup()
	if err != nil {
		log.Error("Parsing common flags failed", "err", err)
		return 1
	}
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
	flag.StringVar(&game, "game", "pingpong", "Which game to play: pingpong or packetflood")
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.BoolVar(&epic, "epic", false, "Enable EPIC")
	flag.BoolVar(&traces, "traces", true, "Enable Jaeger traces")
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
	switch game {
	case "pingpong":
	case "packetflood":
	default:
		integration.LogFatal("Unknown game requested", "game", game)
	}
	log.Info("Flags", "game", game, "traces", traces, "timeout", timeout, "epic", epic, "remote", remote)
}

type server struct {
	packetFloodGame bool
	pongs           uint8 // chosen to overflow.
}

func (s server) run() {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)
	if game == "packetflood" {
		s.packetFloodGame = true
	}

	sdConn := integration.SDConn()
	defer sdConn.Close()
	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcher(""),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		SCIONPacketConnMetrics: scionPacketConnMetrics,
	}
	conn, port, err := connFactory.Register(context.Background(), integration.Local.IA,
		integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	defer conn.Close()
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

	withTag := func(err error) error {
		return err
	}
	if traces {
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
		withTag = func(err error) error {
			tracing.Error(span, err)
			return err
		}
	}

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		))
	}

	// In the packetflood game, we respond to ~0.4% of the pings. Just enough
	// to prove that some pings were received, but not enough to distort
	// performance data by mixing in traffic types.
	if s.packetFloodGame {
		if s.pongs++; s.pongs == 0 {
			return nil
		}
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
	defer c.sdConn.Close()
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	switch game {
	case "pingpong":
		return integration.AttemptRepeatedly("End2End", c.attemptRequest)
	case "packetflood":
		pong_out := make(chan int)
		go func() {
			defer log.HandlePanic()
			totalFailed := 1
			// Drain pongs as long as we get them. We assume that failure means
			// there are no more pongs. We want ro receive at least one pong. The
			// rest doesn't matter.
			integration.RepeatUntilFail("End2End", func(n int) bool {
				failed := c.drainPong(n)
				if !failed {
					totalFailed = 0
				}
				return failed
			})
			pong_out <- totalFailed
		}()

		// We return a "number of failures". So 0 means everything is fine.
		ping_result := integration.RepeatUntilFail("End2End", c.blindPing)
		pong_result := <-pong_out
		return ping_result + pong_result
	default:
		return 0
	}
}

// attemptRequest sends one ping packet and expect a pong.
// Returns true (which means "stop") *if both worked*.
func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	span, ctx := tracing.NilCtx()
	defer cancel()
	if traces {
		span, ctx = tracing.CtxWith(timeoutCtx, "attempt")
		span.SetTag("attempt", n)
		span.SetTag("src", integration.Local.IA)
		span.SetTag("dst", remote.IA)
		defer span.Finish()
	} else {
		ctx = timeoutCtx
	}
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}

	withTag := func(err error) error {
		return err
	}
	if traces {
		span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
		defer span.Finish()
		withTag = func(err error) error {
			tracing.Error(span, err)
			return err
		}
	}

	// Send ping
	if err := c.ping(ctx, n, path, true); err != nil {
		logger.Error("Could not send packet", "err", withTag(err))
		return false
	}
	// Receive pong
	if err := c.pong(ctx, true); err != nil {
		tracing.Error(span, err)
		logger.Error("Error receiving pong", "err", withTag(err))
		if path != nil {
			c.errorPaths[snet.Fingerprint(path)] = struct{}{}
		}
		return false
	}
	return true
}

// blindping sends one ping packet and expect no response.
// Returns true (which means finished) *if sending failed*
func (c *client) blindPing(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.NilCtx()
	if traces {
		span, ctx = tracing.CtxWith(timeoutCtx, "blindping")
		span.SetTag("blindping", n)
		span.SetTag("src", integration.Local.IA)
		span.SetTag("dst", remote.IA)
		defer span.Finish()
	} else {
		ctx = timeoutCtx
	}
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return true
	}

	withTag := func(err error) error {
		return err
	}

	if traces {
		span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
		defer span.Finish()
		withTag = func(err error) error {
			tracing.Error(span, err)
			return err
		}
	}

	// Send ping
	if err := c.ping(ctx, n, path, false); err != nil {
		logger.Error("Could not send packet", "err", withTag(err))
		return true
	}

	return false // Don't stop. Do it again!
}

// drainPong consumes any pong message that might be received.
func (c *client) drainPong(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.NilCtx()
	if traces {
		span, ctx = tracing.CtxWith(timeoutCtx, "drainpong")
		span.SetTag("drainpong", n)
		span.SetTag("dst", integration.Local.IA)
		span.SetTag("src", remote.IA)
		defer span.Finish()
	} else {
		ctx = timeoutCtx
	}
	logger := log.FromCtx(ctx)
	if err := c.pong(ctx, false); err != nil {
		if traces {
			tracing.Error(span, err)
		}
		logger.Error("Error receiving pong", "err", err)
		return true // Stop. The test failed to elicit a single response.
	}
	return false // Don't stop; keep consuming pongs
}

func (c *client) ping(ctx context.Context, n int, path snet.Path, log_ok bool) error {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
	if err != nil {
		return serrors.WrapStr("packing ping", err)
	}
	if err := c.conn.SetWriteDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting write deadline", err)
	}
	if remote.NextHop == nil {
		remote.NextHop = &net.UDPAddr{
			IP:   remote.Host.IP,
			Port: topology.EndhostPort,
		}
	}

	remoteHostIP, ok := netip.AddrFromSlice(remote.Host.IP)
	if !ok {
		return serrors.New("invalid remote host IP", "ip", remote.Host.IP)
	}
	localHostIP, ok := netip.AddrFromSlice(integration.Local.Host.IP)
	if !ok {
		return serrors.New("invalid local host IP", "ip", integration.Local.Host.IP)
	}
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(remoteHostIP),
			},
			Source: snet.SCIONAddress{
				IA:   integration.Local.IA,
				Host: addr.HostIP(localHostIP),
			},
			Path: remote.Path,
			Payload: snet.UDPPayload{
				SrcPort: c.port,
				DstPort: uint16(remote.Host.Port),
				Payload: rawPing,
			},
		},
	}
	if log_ok {
		log.Info("sending ping", "attempt", n, "path", path)
	}
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
	// If all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	// Select first path that didn't error before.
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
	// Extract forwarding path from the SCION Daemon response.
	// If the epic flag is set, try to use the EPIC path type header.
	if epic {
		scionPath, ok := path.Dataplane().(snetpath.SCION)
		if !ok {
			return nil, serrors.New("provided path must be of type scion")
		}
		epicPath, err := snetpath.NewEPICDataplanePath(scionPath, path.Metadata().EpicAuths)
		if err != nil {
			return nil, err
		}
		remote.Path = epicPath
	} else {
		remote.Path = path.Dataplane()
	}
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) pong(ctx context.Context, log_ok bool) error {
	if err := c.conn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
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
	if log_ok {
		log.Info("Received pong", "server", p.Source)
	}
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
