// Copyright 2023 SCION Association
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

// This is a client/server code for use by end2end tests. This one plays
// a variant of ping-pong where the client to send back-to-back pings to the
// server until the sending fails or some deadline was reached. In this case
// the client isn't waiting for responses. The client checks at the end
// whether at least one response has been received. The server responds rarely.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

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
}

type Pong struct {
	Client  addr.IA `json:"client"`
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
}

var (
	remote                 snet.UDPAddr
	timeout                = &util.DurWrap{Duration: 90 * time.Second}
	scionPacketConnMetrics = metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter      = scionPacketConnMetrics.SCMPErrors
	epic                   bool
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

	if integration.Mode == integration.ModeServer {
		(&server{}).run()
		return 0
	}
	c := client{}
	return c.run()
}

func addFlags() {
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for completing the whole test")
	flag.BoolVar(&epic, "epic", false, "Enable EPIC")
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
	log.Info("Flags", "timeout", timeout, "epic", epic, "remote", remote)
}

type server struct {
	pongs uint8 // chosen to overflow.
}

func (s *server) run() {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

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

func (s *server) handlePing(conn snet.PacketConn) error {
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

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		)
	}

	// In this game, we respond to 1/256 (~0.4%) of the pings. Just enough
	// to prove that some pings were received, but not enough to distort
	// performance data by mixing in traffic types.
	if s.pongs++; s.pongs != 0 {
		return nil
	}
	log.Info(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
	raw, err := json.Marshal(Pong{
		Client:  p.Source.IA,
		Server:  integration.Local.IA,
		Message: pong,
	})
	if err != nil {
		return serrors.WrapStr("packing pong", err)
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
		return serrors.New("unexpected path", "type", common.TypeOf(p.Path))
	}
	replypather := snet.DefaultReplyPather{}
	replyPath, err := replypather.ReplyPath(rpath)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	p.Path = replyPath
	// Send pong
	if err := conn.WriteTo(&p, &ov); err != nil {
		return serrors.WrapStr("sending reply", err)
	}
	log.Info("Sent pong to", "client", p.Destination)
	return nil
}

type client struct {
	conn   snet.PacketConn
	port   uint16
	sdConn daemon.Connector
	path   snet.Path
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

	// Drain pongs in the background
	pongOut := make(chan int)
	go func() {
		defer log.HandlePanic()

		// The timeout extends over the entire test. When we don't need to drain any more
		// we just cancel it.
		ctx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
		defer cancel()

		// Drain pongs as long as we get them. We assume that failure means
		// there are no more pongs. We want ro receive at least one pong. The
		// rest doesn't matter.
		allFailed := 1
		integration.RepeatUntilFail("End2EndBlast", func(n int) bool {

			if err := c.pong(ctx); err != nil {
				// We should receive at least one, but this runs until pings stop
				// coming, so there will always be one failure in the end.
				return true // Stop.
			}
			allFailed = 0
			return false // Keep consuming pongs
		})
		pongOut <- allFailed
	}()

	// Same here, the timeout context lives on for the rest of the test (so we don't keep
	// creating and discarding contexts).
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()

	// Get a path, then use it for all the repeats
	p, err := c.getRemote(ctx)
	if err != nil {
		integration.LogFatal("Could not get remote", "err", err)
		return 1
	}
	c.path = p // struct fields cannot be assigned with :=

	// We return a "number of failures". So 0 means everything is fine.
	pingResult := integration.RepeatUntilFail("End2EndBlast", func(n int) bool {
		// Send ping
		if err := c.ping(ctx, n, c.path); err != nil {
			logger := log.FromCtx(ctx)
			logger.Error("Could not send packet", "err", err)
			return true
		}

		return false // Don't stop. Do it again!
	})

	// Stop drainPongs, so we're not stuck here for up to 10s.
	c.conn.Close()

	pongResult := <-pongOut
	if pongResult != 0 {
		log.Info("Never got a single pong")
	}
	return pingResult + pongResult
}

func (c *client) ping(ctx context.Context, n int, path snet.Path) error {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
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
	if err := c.conn.WriteTo(pkt, remote.NextHop); err != nil {
		return err
	}
	return nil
}

func (c *client) getRemote(ctx context.Context) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemon.PathReqFlags{Refresh: false})
	if err != nil {
		return nil, serrors.WrapStr("requesting paths", err)
	}
	// Select first path
	if len(paths) == 0 {
		return nil, serrors.New("no path found")
	}
	path := paths[0]

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

func (c *client) pong(ctx context.Context) error {
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
