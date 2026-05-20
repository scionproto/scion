// Copyright 2026 ETH Zurich
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

package squic_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/private/serrors"
	hummlib "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/keyconf"
)

const (
	hbirdTestResID        = uint32(1)
	hbirdTestBandwidth    = uint16(2)
	hbirdTestDuration     = uint16(9)
	hbirdTestStartOffset  = -2 * time.Second
	tinyServerDaemonAddr  = "127.0.0.19:30255"
	tinyClientDaemonAddr  = "[fd00:f00d:cafe::7f00:b]:30255"
	tinyServerListenAddr  = "1-ff00:0:111,127.0.0.20:12345"
	tinyClientListenAddr  = "1-ff00:0:112,[fd00:f00d:cafe::7f00:c]:0"
	tinyServerRemoteAddr  = "1-ff00:0:111,127.0.0.20:12345"
	quicTestMessageSize   = 20 * 1024
	quicTestMessageServer = "pong over scion"
)

// Keep the client payload at or above 20 KiB so the live test exercises
// multiple data packets instead of succeeding on only a few packets.
var quicTestMessageClient = bytes.Repeat([]byte("ping over hummingbird|"), 1024)[:quicTestMessageSize]

// TestQUICOverHummingbirdTinyTopology verifies that a QUIC handshake plus a
// stream exchange succeeds when the client sends over a Hummingbird reservation
// path in the running tiny topology.
func TestQUICOverHummingbirdTinyTopology(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live tiny-topology test in short mode")
	}
	if os.Getenv("SCION_RUN_LIVE_TESTS") == "" {
		t.Skip("set SCION_RUN_LIVE_TESTS=1 to run live tiny-topology tests")
	}

	keysRoot := requireTinyTopologyAssets(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverDaemon := requireDaemonConnector(t, ctx, tinyServerDaemonAddr)
	clientDaemon := requireDaemonConnector(t, ctx, tinyClientDaemonAddr)
	defer serverDaemon.Close()
	defer clientDaemon.Close()

	serverTopo, err := daemon.LoadTopology(ctx, serverDaemon)
	require.NoError(t, err)
	clientTopo, err := daemon.LoadTopology(ctx, clientDaemon)
	require.NoError(t, err)

	serverLocal := mustParseSCIONUDPAddr(t, tinyServerListenAddr)
	clientLocal := mustParseSCIONUDPAddr(t, tinyClientListenAddr)
	serverRemote := mustParseSCIONUDPAddr(t, tinyServerRemoteAddr)

	serverBasePath := requireBasePath(t, ctx, serverDaemon, serverLocal.IA, clientLocal.IA)
	replyPather := fixedReplyPather{Path: serverBasePath.Dataplane()}
	serverConn := requireSCIONConn(t, ctx, serverTopo, serverLocal.Host, replyPather, true)
	defer serverConn.Close()

	clientConn := requireSCIONConn(t, ctx, clientTopo, clientLocal.Host, nil, false)
	defer clientConn.Close()

	remote := buildHummingbirdRemote(t, ctx, clientDaemon, clientLocal, serverRemote, keysRoot)
	if _, ok := remote.Path.(*snetpath.Reservation); !ok {
		t.Fatalf("expected hummingbird reservation path, got %T", remote.Path)
	}
	t.Logf("dial target path type: %T", remote.Path)

	listener, err := quic.Listen(serverConn, tlsConfig(t), nil)
	require.NoError(t, err)
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runQUICServer(ctx, listener)
	}()

	clientTransport := &quic.Transport{Conn: clientConn}
	defer clientTransport.Close()

	session, err := clientTransport.Dial(ctx, remote, tlsConfig(t), nil)
	require.NoErrorf(t, err,
		"QUIC dial timed out or failed; this usually means the initial Hummingbird "+
			"packet was dropped before the server could reply")
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStreamSync(ctx)
	require.NoError(t, err)
	defer stream.Close()

	_, err = stream.Write(quicTestMessageClient)
	require.NoError(t, err)

	reply := make([]byte, len(quicTestMessageServer))
	n, err := io.ReadFull(stream, reply)
	require.NoError(t, err)
	require.Equal(t, quicTestMessageServer, string(reply[:n]))

	require.NoError(t, <-serverErr)
}

type fixedReplyPather struct {
	Path snet.DataplanePath
}

func (p fixedReplyPather) ReplyPath(snet.RawPath) (snet.DataplanePath, error) {
	return p.Path, nil
}

type ignoreSCMP struct{}

func (ignoreSCMP) Handle(*snet.Packet) error {
	return nil
}

func requireTinyTopologyAssets(t *testing.T) string {
	t.Helper()

	root := filepath.Join(requireRepoRoot(t), "gen")
	if hasTinyTopologyAssets(root) {
		t.Logf("using tiny-topology assets from %s", root)
		return root
	}

	t.Fatalf("tiny topology assets not found in %s", root)
	return ""
}

func hasTinyTopologyAssets(root string) bool {
	required := []string{
		filepath.Join(root, "ASff00_0_110", "keys", "master0.key"),
		filepath.Join(root, "ASff00_0_111", "keys", "master0.key"),
		filepath.Join(root, "ASff00_0_112", "keys", "master0.key"),
		filepath.Join(root, "ASff00_0_111", "topology.json"),
		filepath.Join(root, "ASff00_0_112", "topology.json"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func requireRepoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "resolve current file path")
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func requireDaemonConnector(t *testing.T, ctx context.Context, daemonAddr string) daemon.Connector {
	t.Helper()

	conn, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		t.Fatalf("tiny-topology daemon %s is not reachable: %v", daemonAddr, err)
	}
	if _, err := conn.LocalIA(ctx); err != nil {
		_ = conn.Close()
		t.Fatalf("tiny-topology daemon %s is not usable: %v", daemonAddr, err)
	}
	return conn
}

func requireBasePath(
	t *testing.T,
	ctx context.Context,
	conn daemon.Connector,
	srcIA, dstIA addr.IA,
) snet.Path {
	t.Helper()

	paths, err := conn.Paths(ctx, dstIA, srcIA, types.PathReqFlags{})
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	path := paths[0]
	meta := path.Metadata()
	require.NotNil(t, meta)
	require.Len(t, meta.Interfaces, 4)
	t.Logf("selected base path %s -> %s: %v", srcIA, dstIA, formatInterfaces(meta.Interfaces))
	return path
}

func requireSCIONConn(
	t *testing.T,
	ctx context.Context,
	topology snet.Topology,
	local *net.UDPAddr,
	replyPather snet.ReplyPather,
	ignoreServerSCMP bool,
) *snet.Conn {
	t.Helper()

	var handler snet.SCMPHandler = snet.SCMPPropagationStopper{
		Handler: ignoreSCMP{},
		Log: func(string, ...any) {
			// Keep the live test quiet unless it fails elsewhere.
		},
	}
	if ignoreServerSCMP {
		handler = ignoreSCMP{}
	}
	network := &snet.SCIONNetwork{
		Topology:    topology,
		ReplyPather: replyPather,
		SCMPHandler: handler,
	}
	conn, err := network.Listen(ctx, "udp", local)
	require.NoError(t, err)
	return conn
}

func buildHummingbirdRemote(
	t *testing.T,
	ctx context.Context,
	conn daemon.Connector,
	clientLocal *snet.UDPAddr,
	serverRemote *snet.UDPAddr,
	keysRoot string,
) *snet.UDPAddr {
	t.Helper()

	basePath := requireBasePath(t, ctx, conn, clientLocal.IA, serverRemote.IA)
	reservation := requireHummingbirdReservation(t, basePath, keysRoot, time.Now())
	res, ok := reservation.(*snetpath.Reservation)
	require.True(t, ok, "expected *path.Reservation, got %T", reservation)
	validateReservationWindow(t, res, time.Now())

	remote := serverRemote.Copy()
	remote.Path = reservation
	remote.NextHop = basePath.UnderlayNextHop()

	t.Logf("hummingbird reservation path type: %s", reflect.TypeOf(remote.Path))
	t.Logf("hummingbird next hop: %v", remote.NextHop)
	return remote
}

func requireHummingbirdReservation(
	t *testing.T,
	basePath snet.Path,
	keysRoot string,
	now time.Time,
) snet.DataplanePath {
	t.Helper()

	baseHops := snetpath.InterfacesToBaseHops(basePath.Metadata().Interfaces)
	require.NotEmpty(t, baseHops)

	startTime := uint32(now.Add(hbirdTestStartOffset).Unix())
	aesByIA := make(map[addr.IA]cipher.Block)
	buffer := make([]byte, hummlib.AkBufferSize)
	flyovers := make([]*snetpath.Hop, 0, len(baseHops))
	for _, baseHop := range baseHops {
		block, ok := aesByIA[baseHop.IA]
		if !ok {
			sv := requireSecretValue(t, keysRoot, baseHop.IA)
			var err error
			block, err = aes.NewCipher(sv)
			require.NoError(t, err)
			aesByIA[baseHop.IA] = block
		}
		akRaw := hummlib.DeriveAuthKey(
			block,
			hbirdTestResID,
			hbirdTestBandwidth,
			baseHop.Ingress,
			baseHop.Egress,
			startTime,
			hbirdTestDuration,
			buffer,
		)
		var ak [hummlib.AkBufferSize]byte
		copy(ak[:], akRaw)
		t.Logf("reservation inputs ia=%s in=%d eg=%d res_id=%d bw=%d start=%d dur=%d ak=%s",
			baseHop.IA, baseHop.Ingress, baseHop.Egress, hbirdTestResID,
			hbirdTestBandwidth, startTime, hbirdTestDuration, hex.EncodeToString(ak[:]))
		flyovers = append(flyovers, &snetpath.Hop{
			BaseHop: baseHop,
			Flyover: &snetpath.FlyoverData{
				ResID:     hbirdTestResID,
				Ak:        ak,
				Bw:        hbirdTestBandwidth,
				StartTime: startTime,
				Duration:  hbirdTestDuration,
			},
		})
	}

	reservation, err := snetpath.NewReservation(
		snetpath.WithNow(func() time.Time { return now }),
		snetpath.WithScionPath(basePath, snetpath.FlyoversToMap(flyovers)),
	)
	require.NoError(t, err)
	return reservation
}

func requireSecretValue(t *testing.T, keysRoot string, ia addr.IA) []byte {
	t.Helper()

	keysDir := filepath.Join(
		keysRoot,
		addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
		"keys",
	)
	master, err := keyconf.LoadMaster(keysDir)
	require.NoError(t, err)
	sv := hummlib.DeriveSecretValue(master.Key0)
	t.Logf("secret value ia=%s dir=%s sv=%s", ia, keysDir, hex.EncodeToString(sv))
	return sv
}

func validateReservationWindow(t *testing.T, reservation *snetpath.Reservation, now time.Time) {
	t.Helper()

	for _, hop := range reservation.Hops {
		if hop == nil || hop.Flyover == nil {
			continue
		}
		start := time.Unix(int64(hop.Flyover.StartTime), 0)
		end := start.Add(time.Duration(hop.Flyover.Duration) * time.Second)
		require.Falsef(t, now.Before(start),
			"reservation not yet valid for ia=%s start=%s now=%s", hop.IA, start, now)
		require.Falsef(t, now.After(end),
			"reservation already expired for ia=%s end=%s now=%s", hop.IA, end, now)
	}
}

func runQUICServer(ctx context.Context, listener *quic.Listener) error {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return serrors.Wrap("accepting quic connection", err)
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return serrors.Wrap("accepting quic stream", err)
	}

	buf := make([]byte, len(quicTestMessageClient))
	n, err := io.ReadFull(stream, buf)
	if err != nil {
		return serrors.Wrap("reading client payload", err)
	}
	if !bytes.Equal(buf[:n], quicTestMessageClient) {
		return fmt.Errorf("unexpected client payload")
	}
	if _, err := stream.Write([]byte(quicTestMessageServer)); err != nil {
		return serrors.Wrap("writing server payload", err)
	}
	if err := stream.Close(); err != nil {
		return serrors.Wrap("closing server stream", err)
	}
	return nil
}

func mustParseSCIONUDPAddr(t *testing.T, raw string) *snet.UDPAddr {
	t.Helper()

	addr, err := snet.ParseUDPAddr(raw)
	require.NoError(t, err)
	return addr
}

func formatInterfaces(ifaces []snet.PathInterface) string {
	parts := make([]string, 0, len(ifaces))
	for _, intf := range ifaces {
		parts = append(parts, fmt.Sprintf("%s#%d", intf.IA, intf.ID))
	}
	return strings.Join(parts, " -> ")
}
