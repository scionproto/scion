package multihomed

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/require"
)

var (
	serverIA      = "1-ff00:0:111"
	serverAddress = "127.0.0.1:12345"
	clientAddress = "127.0.0.1:0"
	serverDaemon  = "127.0.0.19:30255" // 111
	clientDaemon  = "127.0.0.27:30255" // 112
)

func TestBasic(t *testing.T) {
	serverAddr := xtest.MustParseUDPAddr(t, serverAddress)
	clientAddr := xtest.MustParseUDPAddr(t, clientAddress)

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	runServerAt(ctx, t, serverAddr)
	runClientWith(ctx, t, serverAddr, clientAddr)
}

func TestMultihomed(t *testing.T) {
	serverAddr := xtest.MustParseUDPAddr(t, serverAddress)
	clientAddr := xtest.MustParseUDPAddr(t, clientAddress)

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	runServerAt(ctx, t, serverAddr)
	runClientWith(ctx, t, serverAddr, clientAddr)
}

func runServerAt(
	ctx context.Context,
	t *testing.T,
	serverAddr *net.UDPAddr,
) {
	sd, err := daemon.NewService(serverDaemon).Connect(ctx)
	require.NoError(t, err)
	defer sd.Close()

	info, err := sd.ASInfo(ctx, 0)
	require.NoError(t, err)
	t.Logf("local IA: %s", info.IA.String())

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

	conn, err := sn.Listen(ctx, "udp", serverAddr)
	require.NoError(t, err)
	require.NotNil(t, conn)

	go func() {
		handlePing(t, conn)
	}()
	t.Log("runServerAt: done")
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
	t.Log("runClientWith: ping sent")

	// Read answer.
	buff := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFrom(buff)
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
	t.Logf("handlePing, remote: %s, read %d bytes", remoteAddr, n)
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
	paths, err := sd.Paths(ctx, remote, local, daemon.PathReqFlags{})
	require.NoError(t, err)
	return paths
}
