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
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/go/godispatcher/network"
	"github.com/scionproto/scion/go/godispatcher/registration"
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
}

func (c *ClientConfig) Run(t *testing.T, f *TestSettings) {
	network, err := snet.NewNetwork(c.PublicAddress.IA, "", f.ApplicationSocket)
	if err != nil {
		t.Errorf("client network init failed, err = %v", err)
	}
	clientConn, err := network.ListenSCION("udp4", c.PublicAddress, 3*time.Second)
	for _, entry := range c.WriteOps {
		_, err := clientConn.WriteToSCION(entry.Message, entry.RemoteAddress)
		if err != nil {
			t.Errorf("client write error, err = %v", err)
		}
	}
	// Kill clients if they don't get the messages quickly
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for _, entry := range c.ReadOps {
		b := make([]byte, 1500)
		n, _, err := clientConn.ReadFromSCION(b)
		if err != nil {
			t.Errorf("client read error, err = %v", err)
		}
		if bytes.Compare(b[:n], entry.Message) != 0 {
			t.Errorf("bad message received, have %v, expect %v", b[:n], entry.Message)
		}
	}
	clientConn.Close()
}

func RunServer(t *testing.T, settings *TestSettings) {
	dispatcher := &network.Dispatcher{
		RoutingTable:      registration.NewIATable(1024, 65535),
		OverlaySocket:     fmt.Sprintf(":%d", settings.OverlayPort),
		ApplicationSocket: settings.ApplicationSocket,
	}
	err := dispatcher.ListenAndServe()
	if err != nil {
		t.Fatalf("dispatcher error, err = %v", err)
	}
}

func TestIntegration(t *testing.T) {
	settings := InitTestSettings(t)
	clients := buildClientConfigs(&settings)

	go RunServer(t, &settings)
	time.Sleep(time.Second)

	var wg sync.WaitGroup
	for _, client := range clients {
		wg.Add(1)
		go func(c *ClientConfig) {
			defer wg.Done()
			c.Run(t, &settings)
		}(client)
	}
	wg.Wait()
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
