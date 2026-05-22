// Copyright 2025 ETH Zurich
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

package multihomed_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
)

// Using test suite declared at multihomed_test.go

// XXX(juagargi) This is not a valid unit test, should be moved to some kind of
// integration test run within a docker container. For now:
//
// Generate the tiny topology with IPv4 only:
// ./scion.sh stop ; rm -r gen/
// ./scion.sh topology -c topology/tiny4.topo
// ./scion.sh start
// Then run the tests:
// go test ./pkg/snet/multihomed -count=1 -v -run TestUDP
// go test ./pkg/snet/multihomed -count=1 -v -run TestBasic
// go test ./pkg/snet/multihomed -count=1 -v -run TestMultihomed

const serverPortInitial = 12345

var (
	serverIA        = "1-ff00:0:111"
	serverIPAddress = "127.0.0.1"
	clientAddress   = "127.0.0.1:0"
	serverDaemon    = "127.0.0.19:30255" // 111
	clientDaemon    = "127.0.0.27:30255" // 112
)

func (s *MultihomedTestSuite) TestUDP() {
	t := s.T()
	t.Parallel()

	// Bind server to any interface.
	serverAddress := fmt.Sprintf("0.0.0.0:%d", s.getServerPort())
	serverAddr := xtest.MustParseUDPAddr(t, serverAddress)

	runUDPServerAt(t, serverAddr)
	runUDPClientWith(t, serverAddr, nil)
}

// TestNoRegressionCheck checks that using bound sockets (like before "multihomed" changes)
// works as expected.
func (s *MultihomedTestSuite) TestNoRegressionCheck() {
	t := s.T()
	t.Parallel()

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	serverAddress := fmt.Sprintf("%s:%d", serverIPAddress, s.getServerPort())
	serverAddr := xtest.MustParseUDPAddr(t, serverAddress)
	clientAddr := xtest.MustParseUDPAddr(t, clientAddress)

	runServerAt(ctx, t, serverAddr)
	runClientWith(ctx, t, serverAddr, clientAddr)
}

// TestMultihomedServer temporary documentation.
// This is a test intended to debug the multihomed scion socket, remove it and make it
// an integration test.
// A multihomed socket is bound to several interfaces, or conversely to an address that spans
// multiple interfaces.
// Multihomed sockets are necessary to get connectivity via several interfaces,
//  1. At the RX side, listening to both cellular and ethernet WAN interfaces: necessary for handling
//     failover one another.
//  2. At the TX side, the ability to use several paths that start on different local interfaces
//     relies on a multihomed socket
func (s *MultihomedTestSuite) TestMultihomedServer() {
	t := s.T()
	t.Parallel()

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	serverAddress := fmt.Sprintf("%s:%d", serverIPAddress, s.getServerPort())
	serverAddr := xtest.MustParseUDPAddr(t, serverAddress)

	runMultihomedServer(ctx, t, serverAddr.Port)
	runClientWith(ctx, t, serverAddr, nil)
}

func runUDPServerAt(
	t *testing.T,
	serverAddr *net.UDPAddr,
) {
	conn, err := net.ListenUDP("udp", serverAddr)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Run in a different thread so that the creation of the server finishes without blocking.
	go func() {
		handleUDPPing(t, conn)
	}()

	t.Log("runUDPServerAt: done")
}

func runServerAt(
	ctx context.Context,
	t *testing.T,
	serverAddr *net.UDPAddr,
) {
	sd, err := daemon.NewService(serverDaemon).Connect(ctx)
	require.NoError(t, err)
	defer sd.Close()

	topo, err := daemon.LoadTopology(ctx, sd)
	require.NoError(t, err)

	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sd},
		},
		Topology: topo,
	}

	conn, err := sn.Listen(ctx, "udp", serverAddr)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Run in a different thread so that the creation of the server finishes without blocking.
	go func() {
		handlePing(t, conn)
	}()
	t.Log("runServerAt: done")
}

func runMultihomedServer(
	ctx context.Context,
	t *testing.T,
	port int,
) {
	sd, err := daemon.NewService(serverDaemon).Connect(ctx)
	require.NoError(t, err)
	defer sd.Close()

	topo, err := daemon.LoadTopology(ctx, sd)
	require.NoError(t, err)

	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sd},
		},
		Topology: topo,
	}

	serverAddr := xtest.MustParseUDPAddr(t, fmt.Sprintf("0.0.0.0:%d", port))
	conn, err := sn.Listen(ctx, "udp", serverAddr)
	require.NoError(t, err)
	require.NotNil(t, conn)

	go func() {
		handlePing(t, conn)
	}()
	t.Log("runServerAt: done")
}

func runUDPClientWith(
	t *testing.T,
	serverAddr *net.UDPAddr,
	clientAddr *net.UDPAddr,
) {
	conn, err := net.DialUDP("udp", clientAddr, serverAddr)
	require.NoError(t, err)

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	t.Logf(" ---> runUDPClientWith: ping sent")

	// Read answer
	buff := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFrom(buff)
	t.Logf(" <--- runUDPClientWith: pong received. Err? %v, remote: %s read %d bytes",
		err != nil, remoteAddr, n)
	require.NoError(t, err)

	buff = buff[:n]
	require.Equal(t, "pong", string(buff))

	err = conn.Close()
	require.NoError(t, err)
}

func runClientWith(
	ctx context.Context,
	t *testing.T,
	serverAddr *net.UDPAddr,
	clientAddr *net.UDPAddr,
) {
	sd, err := daemon.NewService(clientDaemon).Connect(ctx)
	require.NoError(t, err)
	defer sd.Close()

	info, err := sd.ASInfo(ctx, 0)
	require.NoError(t, err)
	t.Logf("client local IA: %s", info.IA.String())

	interfaces, err := sd.Interfaces(ctx)
	require.NoError(t, err)
	for k, v := range interfaces {
		t.Logf("iface %3d: %s", k, v.String())
	}

	topo, err := daemon.LoadTopology(ctx, sd)
	require.NoError(t, err)

	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sd},
		},
		Topology: topo,
	}

	completeServerAddrStr := fmt.Sprintf("%s,[%s]:%d",
		serverIA,
		serverAddr.IP.String(),
		serverAddr.Port)
	completeServerAddr, err := snet.ParseUDPAddr(completeServerAddrStr)
	require.NoError(t, err)

	paths := getRemote(ctx, t, sd, completeServerAddr.IA, info.IA)
	require.Greater(t, len(paths), 0)
	completeServerAddr.Path = paths[0].Dataplane()
	completeServerAddr.NextHop = paths[0].UnderlayNextHop()

	conn, err := sn.Dial(ctx, "udp", clientAddr, completeServerAddr)
	require.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	t.Logf(" ---> runUDPClientWith: ping sent")

	// Read answer.
	buff := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFrom(buff)
	t.Logf(" <--- runClientWith: pong received. Err? %v, remote: %s read %d bytes",
		err != nil, remoteAddr, n)
	require.NoError(t, err)
	require.Equal(t, completeServerAddr.String(), remoteAddr.String())
	buff = buff[:n]
	require.Equal(t, "pong", string(buff))

	err = conn.Close()
	require.NoError(t, err)
}

func handlePing(t *testing.T, conn *snet.Conn) {
	t.Logf("handlePing conn = %p", conn)
	buff := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFrom(buff)
	t.Logf(" ---> handlePing. Err? %v, remote: %s, read %d bytes",
		err != nil, remoteAddr, n)
	require.NoError(t, err)
	buff = buff[:n]
	t.Logf("read from %s", remoteAddr)
	// Check ping.
	require.Equal(t, "ping", string(buff))

	// Pong.
	_, err = conn.WriteTo([]byte("pong"), remoteAddr)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)
}

func handleUDPPing(t *testing.T, conn *net.UDPConn) {
	t.Logf("handleUDPPing conn = %p", conn)
	buff := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFromUDP(buff)
	t.Logf(" <--- handleUDPPing. Err? %v, remote: %s, read %d bytes",
		err != nil, remoteAddr, n)
	require.NoError(t, err)

	buff = buff[:n]
	t.Logf("read from %s", remoteAddr)
	// Check ping.
	require.Equal(t, "ping", string(buff))

	// Pong.
	_, err = conn.WriteTo([]byte("pong"), remoteAddr)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)
}

func getRemote(
	ctx context.Context,
	t *testing.T,
	sd daemon.Connector,
	remote, local addr.IA,
) []snet.Path {
	paths, err := sd.Paths(ctx, remote, local, daemontypes.PathReqFlags{})
	require.NoError(t, err)
	return paths
}

var lastPortUsed atomic.Int32

func (s *MultihomedTestSuite) getServerPort() int {
	// Initialize to 12344 if it's uninitialized.
	lastPortUsed.CompareAndSwap(0, serverPortInitial-1)
	return int(lastPortUsed.Add(1))
}
