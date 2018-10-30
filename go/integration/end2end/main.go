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

	cmn "github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/common"
	integration "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ cmn.Server = (*e2eServer)(nil)

type e2eServer struct {
	conn snet.Conn
}

var _ cmn.Client = (*e2eClient)(nil)

type e2eClient struct {
	conn snet.Conn
}

var (
	ping = "ping:"
	pong = "pong:"
)

func main() {
	cmn.RunClientServer(e2eClient{}, e2eServer{})
}

func (s e2eServer) Run() {
	conn, err := snet.ListenSCION("udp4", &cmn.Local)
	if err != nil {
		cmn.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(integration.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("%s%s\n", integration.ReadySignal, cmn.Local.IA)
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
		if string(b[:pktLen]) != ping+cmn.Local.IA.String() {
			log.Error("Received unexpected data", "data", b[:pktLen])
			break
		}
		log.Debug(fmt.Sprintf("Ping received from %s,%s, sending pong.", addr.IA, addr.Host))
		// Send pong
		reply := []byte(pong + cmn.Local.IA.String() + addr.IA.String())
		_, err = conn.WriteToSCION(reply, addr)
		if err != nil {
			cmn.LogFatal("Unable to send reply", "err", err)
		}
		log.Debug(fmt.Sprintf("Sent pong to %s", addr.Desc()))
	}
}

func (c e2eClient) Run() {
	var err error
	c.conn, err = snet.DialSCION("udp4", &cmn.Local, &cmn.Remote)
	if err != nil {
		cmn.LogFatal("Unable to dial", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())
	for i := 0; i <= cmn.Retries; i++ {
		// Send ping
		if err = c.ping(); err != nil {
			log.Error("Could not send packet", "err", err)
		}
		// Receive pong
		if err, retry := c.pong(); err != nil {
			if !retry {
				cmn.LogFatal("End2end failed", "err", err)
			}
			log.Error("Error receiving pong", "err", err)
			time.Sleep(time.Second / 2)
		} else {
			return
		}
	}
	cmn.LogFatal("End2end failed")
}

func (c e2eClient) ping() error {
	c.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	b := []byte(ping + cmn.Remote.IA.String())
	_, err := c.conn.Write(b)
	return err
}

func (c e2eClient) pong() (error, bool) {
	c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	reply := make([]byte, 1024)
	pktLen, err := c.conn.Read(reply)
	if err != nil {
		if operror, ok := err.(*snet.OpError); ok && operror.SCMP().Type == scmp.T_P_RevokedIF {
			return err, true
		}
		return err, true
	}
	expected := pong + cmn.Remote.IA.String() + cmn.Local.IA.String()
	if string(reply[:pktLen]) != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			string(reply[:pktLen]), "expected", expected), false
	}
	log.Debug(fmt.Sprintf("Received pong from %s", cmn.Remote.IA))
	return nil, false
}
