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

	// The connect client is built differently depending on whether the connection is intra- or
	// inter-AS.
	// The creation of the request and request itself is the same.
	client := hbirdv1connect.NewHBirdServiceClient(
		http.DefaultClient,
		"http://127.0.0.1:30258",
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

	// const redemptionServerAddr = "127.0.0.11"
	const redemptionServerAddr = "127.0.0.1" // For a local server running in the host.
	const redemptionServerPort = 30258
	const as110 = "1-ff00:0:110"
	const localScionDaemonAddr = "127.0.0.19:30255" // As in 111

	dstAddr, err := snet.ParseUDPAddr(
		fmt.Sprintf("%s,%s:%d", as110, redemptionServerAddr, redemptionServerPort))
	require.NoError(t, err)
	// TODO we need a path in dstAddr to the destination, TAL hbird_client.go:220

	sdConn := buildSdConn(ctx, t, localScionDaemonAddr)
	scionNetwork := buildScionNetwork(ctx, t, sdConn)
	factory := buildFactory(ctx, t, scionNetwork)
	dialerGenerator := factory.NewDialer
	// var dialer libconnect.Dialer
	peer := make(chan net.Addr, 1)

	// Before getting the dialer, attach a path to the destination address.
	attachScionPath(ctx, t, sdConn, dstAddr)

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

func attachScionPath(
	ctx context.Context,
	t *testing.T,
	sdConn daemon.Connector,
	dstAddr *snet.UDPAddr,
) {
	localIA, err := sdConn.LocalIA(ctx)
	require.NoError(t, err)

	paths, err := sdConn.Paths(ctx, dstAddr.IA, localIA, types.PathReqFlags{})
	require.NoError(t, err)
	require.Greater(t, len(paths), 0)

	p := paths[0]
	dstAddr.Path = p.Dataplane()
	dstAddr.NextHop = p.UnderlayNextHop()
}

type passThroughRewriter struct{}

func (passThroughRewriter) RedirectToQUIC(_ context.Context, address net.Addr) (net.Addr, error) {
	return address, nil
}
