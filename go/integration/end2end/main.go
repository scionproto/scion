// Copyright 2018 ETH Zurich
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
	"os"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	ping = "ping:"
	pong = "pong:"
)

var (
	remote snet.Addr
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
	} else {
		return client{}.run()
	}
}

func addFlags() {
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
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
	}
}

type server struct {
	conn snet.Conn
}

func (s server) run() {
	conn, err := snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", conn.LocalAddr().(*snet.Addr).Host.L4.Port())
		fmt.Printf("%s%s\n", libint.ReadySignal, integration.Local.IA)
	}
	log.Debug("Listening", "local", conn.LocalAddr())
	// Receive ping message
	b := make(common.RawBytes, 1024)
	for {
		pktLen, addr, err := conn.ReadFromSCION(b)
		if err != nil {
			log.Error("Error reading packet", "err", err)
			continue
		}
		if string(b[:pktLen]) != ping+integration.Local.IA.String() {
			integration.LogFatal("Received unexpected data", "data", b[:pktLen])
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", addr))
		// Send pong
		reply := pongMessage(integration.Local.IA, addr.IA)
		_, err = conn.WriteToSCION(reply, addr)
		if err != nil {
			integration.LogFatal("Unable to send reply", "err", err)
		}
		log.Debug(fmt.Sprintf("Sent pong to %s", addr.Desc()))
	}
}

type client struct {
	conn   snet.Conn
	sdConn sciond.Connector
}

func (c client) run() int {
	var err error
	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())
	c.sdConn = snet.DefNetwork.Sciond()
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	// Send ping
	if err := c.ping(n); err != nil {
		log.Error("Could not send packet", "err", err)
		return false
	}
	// Receive pong
	if err := c.pong(); err != nil {
		log.Debug("Error receiving pong", "err", err)
		return false
	}
	return true
}

func (c client) ping(n int) error {
	if err := c.getRemote(n); err != nil {
		return err
	}
	c.conn.SetWriteDeadline(time.Now().Add(integration.DefaultIOTimeout))
	b := pingMessage(remote.IA)
	_, err := c.conn.WriteTo(b, &remote)
	return err
}

func (c client) getRemote(n int) error {
	if remote.IA.Eq(integration.Local.IA) {
		return nil
	}
	// Get paths from sciond
	ctx, cancelF := context.WithTimeout(context.Background(), libint.CtxTimeout)
	defer cancelF()
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

func (c client) pong() error {
	c.conn.SetReadDeadline(time.Now().Add(integration.DefaultIOTimeout))
	reply := make([]byte, 1024)
	pktLen, err := c.conn.Read(reply)
	if err != nil {
		return common.NewBasicError("Error reading packet", err)
	}
	expected := pong + remote.IA.String() + integration.Local.IA.String()
	if string(reply[:pktLen]) != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			string(reply[:pktLen]), "expected", expected)
	}
	log.Debug(fmt.Sprintf("Received pong from %s", remote.IA))
	return nil
}

func pingMessage(server addr.IA) []byte {
	return []byte(ping + server.String())
}

func pongMessage(server, client addr.IA) []byte {
	return []byte(pong + server.String() + client.String())
}
