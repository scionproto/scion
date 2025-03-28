package multihomed

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/require"
)

func TestMultihomed(t *testing.T) {
	serverAddress := "127.0.0.1:12345"
	clientAddress := "127.0.0.1:0"
	serverDaemon := "127.0.0.19:30255" // 111
	clientDaemon := "127.0.0.27:30255" // 112

	serverAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	require.NoError(t, err)
	clientAddr, err := net.ResolveUDPAddr("udp", clientAddress)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	{ // Server
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
		defer conn.Close()

		go func() {
			handlePing(t, conn)
		}()
	}

	{ // Client
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

		completeServerAddrStr := fmt.Sprintf("1-ff00:0:111,[%s]:%d",
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
