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
	"encoding/json"
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
	ping = "ping"
	pong = "pong"
)

var (
	remote  snet.Addr
	replies int
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
	flag.IntVar(&replies, "replies", 10, "Number of replies sent by the server")
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
		p, err := PingFromRaw(b[:pktLen])
		if err != nil {
			integration.LogFatal("Received unparsable ping", "err", err)
		}
		pongs, err := PongsFromPing(p, addr.IA)
		if err != nil {
			integration.LogFatal("Cannot create pongs from ping", "err", err)
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", addr))
		// Send pongs
		for _, pong := range pongs {
			reply, err := pong.Pack()
			if err != nil {
				integration.LogFatal("Unable to pack reply", "err", err)
			}
			_, err = conn.WriteToSCION(reply, addr)
			if err != nil {
				integration.LogFatal("Unable to send reply", "err", err)
			}
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
	if err := c.pong(n); err != nil {
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
	p := Ping{
		Attempt:  n,
		Messages: replies,
		Server:   remote.IA,
	}
	b, err := p.Pack()
	if err != nil {
		return err
	}
	_, err = c.conn.WriteTo(b, &remote)
	return err
}

func (c client) getRemote(n int) error {
	if remote.IA.Equal(integration.Local.IA) {
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

func (c client) pong(n int) error {
	c.conn.SetReadDeadline(time.Now().Add(integration.DefaultIOTimeout))

	pongs := make(map[int]Pong, replies)

	reply := make([]byte, 1024)
	for i := 0; i < replies; i++ {
		pktLen, err := c.conn.Read(reply)
		if err != nil {
			return common.NewBasicError("Error reading packet", err)
		}
		p, err := PongFromRaw(reply[:pktLen])
		if err != nil {
			return common.NewBasicError("Received unparsable pong", err)
		}
		if !p.Client.Equal(integration.Local.IA) {
			return common.NewBasicError("Received pong for different client", nil, "ia", p.Client)
		}
		if !p.Server.Equal(remote.IA) {
			return common.NewBasicError("Received pong from different server", nil, "ia", p.Server)
		}
		if p.Attempt != n {
			log.Error("Skipping pong for wrong attempt", "expected", n, "actual", p.Attempt)
			i--
			continue
		}
		pongs[p.Message] = p
		log.Debug("Received pong", "remote", remote.IA, "attempt", n, "message", p.Message)
	}
	if len(pongs) != replies {
		return common.NewBasicError("not enough pongs received", nil, "count", len(pongs))
	}
	return nil
}

type Ping struct {
	Type     string
	Server   addr.IA
	Attempt  int
	Messages int
}

func PingFromRaw(raw []byte) (Ping, error) {
	var p Ping
	if err := json.Unmarshal(raw, &p); err != nil {
		return Ping{}, err
	}
	if p.Type != ping {
		return Ping{}, common.NewBasicError("invalid type", nil, "type", p.Type)
	}
	return p, nil
}

func (p Ping) Pack() ([]byte, error) {
	p.Type = ping
	return json.Marshal(p)
}

type Pong struct {
	Type    string
	Server  addr.IA
	Client  addr.IA
	Attempt int
	Message int
}

func PongFromRaw(raw []byte) (Pong, error) {
	var p Pong
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pong{}, err
	}
	if p.Type != pong {
		return Pong{}, common.NewBasicError("invalid type", nil, "type", p.Type)
	}
	return p, nil
}

func PongsFromPing(p Ping, client addr.IA) ([]Pong, error) {
	if !integration.Local.IA.Equal(p.Server) {
		return nil, common.NewBasicError("Ping for different server", nil, "ia", p.Server)
	}
	pongs := make([]Pong, p.Messages)
	for i := range pongs {
		pongs[i] = Pong{
			Type:    pong,
			Server:  integration.Local.IA,
			Client:  client,
			Attempt: p.Attempt,
			Message: i,
		}
	}
	return pongs, nil
}

func (p Pong) Pack() ([]byte, error) {
	p.Type = pong
	return json.Marshal(p)
}
