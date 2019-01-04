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
	"bytes"
	"io/ioutil"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestSettings struct {
	ApplicationSocket string
	OverlayPort       int
}

func buildClientConfigs(settings *TestSettings) []*ClientConfig {
	clientAddresses := map[string]*snet.Addr{
		"public-only-1": {
			IA: xtest.MustParseIA("1-ff00:0:1"),
			Host: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				L4: addr.NewL4UDPInfo(8080),
			},
			NextHop: MustNewOverlayAddr(
				addr.HostFromIP(net.IP{127, 0, 0, 1}),
				addr.NewL4UDPInfo(uint16(settings.OverlayPort)),
			),
		},
		"public-only-2": {
			IA: xtest.MustParseIA("1-ff00:0:1"),
			Host: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				L4: addr.NewL4UDPInfo(8081),
			},
			NextHop: MustNewOverlayAddr(
				addr.HostFromIP(net.IP{127, 0, 0, 1}),
				addr.NewL4UDPInfo(uint16(settings.OverlayPort)),
			),
		},
	}
	return []*ClientConfig{
		{
			PublicAddress: clientAddresses["public-only-1"],
			WriteOps: []Op{
				{
					RemoteAddress: clientAddresses["public-only-2"],
					Message:       []byte{1, 2, 3, 4, 5},
				},
			},
		},
		{
			PublicAddress: clientAddresses["public-only-2"],
			ReadOps: []Op{
				{
					RemoteAddress: clientAddresses["public-only-1"],
					Message:       []byte{1, 2, 3, 4, 5},
				},
			},
		},
	}
}

func InitTestSettings(t *testing.T) TestSettings {
	ringbuf.InitMetrics("dispatcher", nil, nil)
	socketName, err := getSocketName("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	return TestSettings{
		ApplicationSocket: socketName,
		OverlayPort:       40013,
	}
}

type OpSequence []Op

type Op struct {
	RemoteAddress *snet.Addr
	Message       []byte
}

type ClientConfig struct {
	PublicAddress *snet.Addr
	// WriteOps contains the network writes each client does at start-up.
	WriteOps OpSequence
	// ReadOps contains the messages (and remote address) each client expects.
	ReadOps OpSequence
	// conn is the cached connection after the client starts listening
	conn snet.Conn
}

func (c *ClientConfig) Listen(t *testing.T, settings *TestSettings) {
	network, err := snet.NewNetwork(c.PublicAddress.IA, "", settings.ApplicationSocket)
	if err != nil {
		t.Fatalf("client network init failed, err = %v", err)
	}
	clientConn, err := network.ListenSCION("udp4", c.PublicAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("client conn init failed, err = %v", err)
	}
	c.conn = clientConn
}

func (c *ClientConfig) DoWriteOps(t *testing.T) {
	for _, entry := range c.WriteOps {
		_, err := c.conn.WriteToSCION(entry.Message, entry.RemoteAddress)
		if err != nil {
			t.Errorf("client write error, aborting future writes, err = %v", err)
			return
		}
	}
}

func (c *ClientConfig) DoReadOps(t *testing.T) {
	// Kill clients if they don't get the messages quickly
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for _, entry := range c.ReadOps {
		b := make([]byte, 1500)
		n, _, err := c.conn.ReadFromSCION(b)
		if err != nil {
			t.Errorf("client read error, aborting future reads, err = %v", err)
			return
		}
		if bytes.Compare(b[:n], entry.Message) != 0 {
			t.Errorf("bad message received, have %v, expect %v", b[:n], entry.Message)
		}
	}
	c.conn.Close()
}

func TestDataplaneIntegration(t *testing.T) {
	settings := InitTestSettings(t)
	clients := buildClientConfigs(&settings)

	go func() {
		err := RunDispatcher(settings.ApplicationSocket, settings.OverlayPort)
		if err != nil {
			t.Fatalf("dispatcher error, err = %v", err)
		}
	}()
	time.Sleep(time.Second)

	InitAllClientConns(t, clients, &settings)
	DoAllWriteOps(t, clients)
	DoAllReadOps(t, clients)
}

func InitAllClientConns(t *testing.T, clients []*ClientConfig, settings *TestSettings) {
	for _, client := range clients {
		client.Listen(t, settings)
	}
}

func DoAllWriteOps(t *testing.T, clients []*ClientConfig) {
	for _, client := range clients {
		client.DoWriteOps(t)
	}
}

func DoAllReadOps(t *testing.T, clients []*ClientConfig) {
	for _, client := range clients {
		client.DoReadOps(t)
	}
}

func getSocketName(dir string) (string, error) {
	dir, err := ioutil.TempDir(dir, "dispatcher")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "server.sock"), nil
}

func MustNewOverlayAddr(l3 addr.HostAddr, l4 addr.L4Info) *overlay.OverlayAddr {
	address, err := overlay.NewOverlayAddr(l3, l4)
	if err != nil {
		panic(err)
	}
	return address
}
