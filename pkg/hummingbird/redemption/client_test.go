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

package redemption

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/stretchr/testify/require"
)

// TestRedeemHop
// Expects the server to run like:
// go run ./hbird/cmd/hummingbird/   --config gen/ASff00_0_110/hbird.toml
// Server needs dummy_keys inside the configuration directory.
func TestRedeemHopLocal(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111

	// Connect to the daemon.
	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)
	// Find the address of the local CS.
	topo := daemon.TopoQuerier{Connector: sdConn}
	csAddr, err := topo.UnderlayAnycast(ctx, addr.SvcCS)
	require.NoError(t, err)
	// Build the redemption server's address using the CS's one.
	dstRedemptionServer := fmt.Sprintf("http://%s:%d", csAddr.IP.String(), redemptionServerPort)

	// The connect client is built differently depending on whether the connection is intra- or
	// inter-AS.
	// The creation of the request and request itself is the same.
	client := hbirdv1connect.NewHBirdServiceClient(
		http.DefaultClient,
		dstRedemptionServer,
	)

	request := &hbirdv1.RedemptionRequests{}
	res, err := client.Redeem(ctx, connect.NewRequest(request))
	require.NoError(t, err)
	require.NotNil(t, res)
}

// TestRedeemHopInterAS
// Expects the server to run like:
// cd hbird/cmd/hummingbird && go run ./ --config configuration/hbird.toml
// The topology file is for AS 110 from tiny.topo
//
// The test client is run as:
// export SCION_DAEMON=$( cd ../../../ && ./scion.sh sciond-addr 111 ) && go run ./ 1-ff00:0:110 skipIP
func TestRedeemHopInterAS(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	const redemptionServerPort = 30258
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111

	dstIA := addr.MustParseIA("1-ff00:0:110")
	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)
	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)
	paths, err := sdConn.Paths(ctx, dstIA, localIA, types.PathReqFlags{})
	require.NoError(t, err)
	chosenPath := paths[0]

	// Construct the redemption server's address based on that of the CS.
	csIpAddr, err := findCsIpAddr(chosenPath, dstIA)
	require.NoError(t, err)
	dstAddr := &snet.UDPAddr{
		IA: dstIA,
		Host: &net.UDPAddr{
			IP:   net.IP(csIpAddr.Addr().AsSlice()),
			Port: redemptionServerPort,
		},
		Path:    chosenPath.Dataplane(),
		NextHop: chosenPath.UnderlayNextHop(),
	}
	scionNetwork := buildScionNetwork(ctx, t, sdConn)
	factory := buildFactory(ctx, t, scionNetwork)
	dialerGenerator := factory.NewDialer
	// var dialer libconnect.Dialer
	peer := make(chan net.Addr, 1)

	dstAddr.Path = chosenPath.Dataplane()
	dstAddr.NextHop = chosenPath.UnderlayNextHop()

	readyDialer := dialerGenerator(dstAddr,
		squic.WithDialTimeout(time.Second),
		squic.WithPeerChannel(peer),
	)

	// The connect client is built differently depending on whether the connection is intra- or
	// inter-AS.
	// The creation of the request and request itself is the same.
	client := hbirdv1connect.NewHBirdServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: readyDialer.DialEarly,
			},
		},
		libconnect.BaseUrl(dstAddr),
	)

	request := &hbirdv1.RedemptionRequests{}
	res, err := client.Redeem(ctx, connect.NewRequest(request))
	require.NoError(t, err)
	require.NotNil(t, res)
}

func buildSdConn(
	ctx context.Context,
	t *testing.T,
	daemonAddr string,
) daemon.Connector {
	conn, err := daemon.NewService(daemonAddr).Connect(ctx)
	require.NoError(t, err)
	return conn
}

func buildScionNetwork(
	ctx context.Context,
	t *testing.T,
	sdConn daemon.Connector,
) *snet.SCIONNetwork {
	topo, err := daemon.LoadTopology(ctx, sdConn)
	require.NoError(t, err)

	scionPacketConnMetrics := metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter := scionPacketConnMetrics.SCMPErrors

	return &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          topo,
	}
}

func buildFactory(
	ctx context.Context,
	t *testing.T,
	sn *snet.SCIONNetwork,
) *squic.EarlyDialerFactory {

	clientAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	}
	client, err := sn.Listen(ctx, "udp", clientAddr)
	require.NoError(t, err)
	clientTransport := &quic.Transport{
		Conn: client,
	}

	insecureClientTlsConfig, err := appnet.GenerateTLSConfig()
	require.NoError(t, err)
	insecureClientTlsConfig.InsecureSkipVerify = true
	insecureClientTlsConfig.NextProtos = []string{"SCION"}

	qConnDialer := &squic.ConnDialer{
		Transport: clientTransport,
		TLSConfig: insecureClientTlsConfig,
	}

	// rewriter := &appnet.AddressRewriter{
	// 	Router: &snet.BaseRouter{
	// 		Querier: appnet.IntraASPathQuerier{
	// 			IA:  topo.IA(),
	// 			MTU: topo.MTU()}},
	// 	SVCRouter: topo,
	// 	Resolver: &svc.Resolver{
	// 		LocalIA: topo.IA(),
	// 		Network: &snet.SCIONNetwork{
	// 			Topology:    clientNet.Topology,
	// 			SCMPHandler: nil,
	// 		},
	// 		LocalIP: clientAddr.IP,
	// 	},
	// }
	rewriter := passThroughRewriter{}

	dialer := &libgrpc.QUICDialer{
		Dialer:   qConnDialer,
		Rewriter: rewriter,
	}

	factory := &squic.EarlyDialerFactory{
		Transport: qConnDialer.Transport,
		TLSConfig: libconnect.AdaptClientTLS(qConnDialer.TLSConfig),
		Rewriter:  dialer.Rewriter,
	}
	return factory
}

type passThroughRewriter struct{}

func (passThroughRewriter) RedirectToQUIC(_ context.Context, address net.Addr) (net.Addr, error) {
	return address, nil
}
