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
	"os"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	ping = "ping:"
	pong = "pong:"
)

var (
	remote  snet.Addr
	timeout = &util.DurWrap{Duration: 2 * time.Second}
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	addFlags()
	integration.Setup()
	validateFlags()
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	return client{}.run()
}

func addFlags() {
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
}

func validateFlags() {
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.L4 == nil {
			integration.LogFatal("Missing remote port")
		}
		if remote.Host.L4.Port() == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.L4.Port())
		}
		if timeout.Duration == 0 {
			integration.LogFatal("Invalid timeout provided", "timeout", timeout)
		}
	}
}

type server struct {
}

func (s server) run() {
	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcherService(""),
		SCMPHandler: snet.NewSCMPHandler(
			pathmgr.New(snet.DefNetwork.Sciond(), pathmgr.Timers{}),
		),
	}
	conn, port, err := connFactory.RegisterTimeout(integration.Local.IA, integration.Local.Host,
		nil, addr.SvcNone, 0)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", port)
		fmt.Printf("%s%s\n", libint.ReadySignal, integration.Local.IA)
	}
	log.Debug("Listening", "local", fmt.Sprintf("%v:%d", integration.Local.Host, port))
	// Receive ping message
	for {
		var p snet.SCIONPacket
		var ov overlay.OverlayAddr
		if err := conn.ReadFrom(&p, &ov); err != nil {
			log.Error("Error reading packet", "err", err)
			continue
		}
		if string(p.Payload.(common.RawBytes)) != ping+integration.Local.IA.String() {
			integration.LogFatal("Received unexpected data", "data", p.Payload.(common.RawBytes))
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.",
			p.Source))
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
		log.Debug(fmt.Sprintf("Sent pong to %s", p.Destination))
	}
}

type client struct {
	conn   snet.PacketConn
	port   uint16
	sdConn sciond.Connector
}

func (c client) run() int {
	connFactory := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliable.NewDispatcherService(""),
		SCMPHandler: snet.NewSCMPHandler(
			pathmgr.New(snet.DefNetwork.Sciond(), pathmgr.Timers{}),
		),
	}

	var err error
	c.conn, c.port, err = connFactory.RegisterTimeout(integration.Local.IA, integration.Local.Host,
		nil, addr.SvcNone, 0)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local",
		fmt.Sprintf("%v,[%v]:%d", integration.Local.IA, integration.Local.Host.L3, c.port))
	c.sdConn = snet.DefNetwork.Sciond()
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	// Send ping
	if err := c.ping(ctx, n); err != nil {
		log.Error("Could not send packet", "err", err)
		return false
	}
	// Receive pong
	if err := c.pong(ctx); err != nil {
		log.Debug("Error receiving pong", "err", err)
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
		var err error
		remote.NextHop, err = overlay.NewOverlayAddr(
			remote.Host.L3,
			addr.NewL4UDPInfo(overlay.EndhostPort),
		)
		if err != nil {
			return common.NewBasicError("Error building overlay", err)
		}
	}
	var debugID [common.ExtnFirstLineLen]byte
	// API guarantees return values are ok
	_, _ = rand.Read(debugID[:])
	return c.conn.WriteTo(
		&snet.SCIONPacket{
			SCIONPacketInfo: snet.SCIONPacketInfo{
				Destination: snet.SCIONAddress{
					IA:   remote.IA,
					Host: remote.Host.L3,
				},
				Source: snet.SCIONAddress{
					IA:   integration.Local.IA,
					Host: integration.Local.Host.L3,
				},
				Path: remote.Path,
				Extensions: []common.Extension{
					layers.ExtnE2EDebug{
						ID: debugID,
					},
				},
				L4Header: &l4.UDP{
					SrcPort: c.port,
					DstPort: remote.Host.L4.Port(),
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
	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA, 1,
		sciond.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return common.NewBasicError("Error requesting paths", err)
	}
	if len(paths.Entries) == 0 {
		return common.NewBasicError("No path entries found", nil)
	}
	pathEntry := paths.Entries[0]
	path := spath.New(pathEntry.Path.FwdPath)
	if err = path.InitOffsets(); err != nil {
		return common.NewBasicError("Unable to initialize path", err)
	}
	// Extract forwarding path from sciond response
	remote.Path = path
	remote.NextHop, err = pathEntry.HostInfo.Overlay()
	if err != nil {
		return common.NewBasicError("Error getting overlay", err)
	}
	return nil
}

func (c client) pong(ctx context.Context) error {
	c.conn.SetReadDeadline(getDeadline(ctx))
	var p snet.SCIONPacket
	var ov overlay.OverlayAddr
	if err := c.conn.ReadFrom(&p, &ov); err != nil {
		return common.NewBasicError("Error reading packet", err)
	}
	expected := pong + remote.IA.String() + integration.Local.IA.String()
	if string(p.Payload.(common.RawBytes)) != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			string(p.Payload.(common.RawBytes)), "expected", expected)
	}
	log.Debug(fmt.Sprintf("Received pong from %s", remote.IA))
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
