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
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	ping = "ping:"
	pong = "pong:"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	integration.Setup()
	if integration.Mode == integration.ModeServer {
		e2eServer{}.run()
		return 0
	} else {
		return e2eClient{}.run()
	}
}

type e2eServer struct {
	conn snet.Conn
}

func (s e2eServer) run() {
	conn, err := snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
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

type e2eClient struct {
	conn snet.Conn
}

func (c e2eClient) run() int {
	var err error
	c.conn, err = snet.DialSCION("udp4", &integration.Local, &integration.Remote)
	if err != nil {
		integration.LogFatal("Unable to dial", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())
	ticker := time.NewTicker(integration.RetryTimeout)
	defer ticker.Stop()
	tries := 0
	for range ticker.C {
		tries++
		if c.attemptPingPong() {
			return 0
		} else if tries < integration.Attempts {
			log.Info("Retrying...")
			continue
		}
		log.Error("End2end failed. No more attempts...")
		break
	}
	return 1
}

func (c e2eClient) attemptPingPong() bool {
	// Send ping
	if err := c.ping(); err != nil {
		log.Error("Could not send packet", "err", err)
		return false
	}
	// Receive pong
	if err := c.pong(); err != nil {
		log.Error("Error receiving pong", "err", err)
		return false
	}
	return true
}

func (c e2eClient) ping() error {
	c.conn.SetWriteDeadline(time.Now().Add(integration.DefaultIOTimeout))
	b := pingMessage(integration.Remote.IA)
	_, err := c.conn.Write(b)
	return err
}

func (c e2eClient) pong() error {
	c.conn.SetReadDeadline(time.Now().Add(integration.DefaultIOTimeout))
	reply := make([]byte, 1024)
	pktLen, err := c.conn.Read(reply)
	if err != nil {
		return err
	}
	expected := pong + integration.Remote.IA.String() + integration.Local.IA.String()
	if string(reply[:pktLen]) != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			string(reply[:pktLen]), "expected", expected)
	}
	log.Debug(fmt.Sprintf("Received pong from %s", integration.Remote.IA))
	return nil
}

func pingMessage(server addr.IA) []byte {
	return []byte(ping + server.String())
}

func pongMessage(server, client addr.IA) []byte {
	return []byte(pong + server.String() + client.String())
}
