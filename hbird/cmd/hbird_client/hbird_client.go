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

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/daemon"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/connect/happy"
	libgrpc "github.com/scionproto/scion/pkg/grpc"

	//slog "github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"

	//hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
)

const RedemptionPort = 30258

func main() {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	/*defer slog.Flush()
	if err := slog.Setup(slog.Config{Console: slog.ConsoleConfig{Level: "debug"}}); err != nil {
		fmt.Printf("setting up log %v", err)
	}*/
	remoteAS := func([]string) string {
		if len(os.Args) <= 1 {
			return ""
		}
		dIA, err := addr.ParseIA(os.Args[1])
		if err != nil {
			return ""
		}
		return dIA.String()
	}(os.Args)
	skipIP := (len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "skipIP")) ||
		(len(os.Args) > 2 && strings.HasPrefix(os.Args[2], "skipIP"))
	rpcType := func([]string) string {
		if len(os.Args) <= 3 {
			return ""
		}
		return os.Args[3]
	}(os.Args)

	fmt.Printf("remoteAS = %s\n", remoteAS)
	fmt.Printf("skipIP   = %v\n", skipIP)
	fmt.Printf("rcpType  = %s\n", rpcType)

	if !skipIP {
		client := hbirdv1connect.NewHBirdServiceClient(
			http.DefaultClient,
			fmt.Sprintf("http://localhost:%d", RedemptionPort),
		)
		res, err := client.Status(
			context.Background(),
			connect.NewRequest(&emptypb.Empty{}),
		)
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Status response:", res.Msg.Version)
	}

	if remoteAS != "" {
		testSCION(remoteAS, rpcType)
	}
}

func testSCION(remoteAS, rpcType string) {
	ctx := context.Background()

	// topo, err := topology.NewLoader(topology.LoaderCfg{
	// 	File:   "/etc/scion/topology.json",
	// 	Reload: app.SIGHUPChannel(ctx),
	// })
	// if err != nil {
	// 	fmt.Println("Error creating topology loader", err)
	// 	return
	// }

	var envFlags flag.SCIONEnvironment
	err := envFlags.LoadExternalVars()
	if err != nil {
		fmt.Printf("loading external variables: %s\n", err)
	}
	daemonAddr := envFlags.Daemon()
	fmt.Printf("scion daemon at %s\n", daemonAddr)
	sd, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		fmt.Println("connecting to SCION Daemon", err)
		return
	}
	defer sd.Close()

	localIA, err := sd.LocalIA(ctx)
	if err != nil {
		fmt.Printf("getting local IA: %s\n", err)
	}
	fmt.Printf("local IA = %s\n", localIA)

	topo, err := daemon.LoadTopology(ctx, sd)
	if err != nil {
		fmt.Printf("loading topology: %s\n", err)
		return
	}

	clientNet := &snet.SCIONNetwork{
		Topology: topo,
	}
	clientAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	}

	rewriter := passThroughRewriter{}

	client, err := clientNet.Listen(ctx, "udp", clientAddr)
	if err != nil {
		fmt.Println("Error creating SCION client socket", err)
		return
	}
	defer client.Close()
	ephemeralTLSConfig, err := appnet.GenerateTLSConfig()
	if err != nil {
		fmt.Println("Error generating TLS config", err)
		return
	}
	insecureClientTLSConfig := ephemeralTLSConfig
	insecureClientTLSConfig.InsecureSkipVerify = true
	insecureClientTLSConfig.NextProtos = []string{"SCION"}

	clientTransport := &quic.Transport{
		Conn: client,
	}
	qs := &squic.ConnDialer{
		Transport: clientTransport,
		TLSConfig: insecureClientTLSConfig,
	}

	dialer := &libgrpc.QUICDialer{
		Rewriter: rewriter,
		Dialer:   qs,
	}
	requester := Requester{
		Connect: ConnectRequester{
			Dialer: (&squic.EarlyDialerFactory{
				Transport: qs.Transport,
				TLSConfig: libconnect.AdaptClientTLS(qs.TLSConfig), // Adds h3 to NextProtos
				Rewriter:  dialer.Rewriter,
			}).NewDialer,
		},
		Grpc: GrpcRequester{
			Dialer: &libgrpc.QUICDialer{
				Rewriter: rewriter,
				Dialer: &squic.ConnDialer{
					Transport: clientTransport,
					TLSConfig: insecureClientTLSConfig,
				},
			},
		},
	}

	opts := []path.Option{
		// //path.WithRefresh(true),
		// path.WithSequence("0* 71-1916#3 0*"),
		// /*path.WithProbing(&path.ProbeConfig{
		// 	LocalIA: topo.IA(),
		// 	LocalIP: clientAddr.IP,
		// }),*/
	}
	dstIA, err := addr.ParseIA(remoteAS)
	if err != nil {
		fmt.Printf("parsing the remote IA \"%s\": %s\n", remoteAS, err)
	}
	path, err := path.Choose(ctx, sd, dstIA, opts...)
	if err != nil {
		fmt.Printf("choosing paths: %s\n", err)
		return
	}
	fmt.Println("control plane path:", path)

	// IP address of the CS in the dstIA.
	ipAddr, err := findCsIpAddr(path, dstIA)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// Change its port to that of the redemption server.
	ipAddr = netip.AddrPortFrom(ipAddr.Addr(), RedemptionPort)
	destSAddr, err := snet.ParseUDPAddr(remoteAS + "," + ipAddr.String())
	if err != nil {
		fmt.Println("Error parsing destination address", err)
	}

	fmt.Printf("Redemption server at %s\n", destSAddr.String())
	destSAddr.Path = path.Dataplane()
	destSAddr.NextHop = path.UnderlayNextHop()
	// fmt.Println("dataplane path:", destSAddr.Path)

	nCtx := context.Background()
	if rpcType != "" {
		nCtx = context.WithValue(nCtx, "rpc", rpcType)
	}
	//fmt.Println("destSAddr", destSAddr)
	resp, err := requester.Status(nCtx, emptypb.Empty{}, destSAddr)
	if err != nil {
		fmt.Println("Error requesting status", err)
		return
	}
	fmt.Println("Status response:", resp.Version)
}

type Requester struct {
	Connect RPC
	Grpc    RPC
}

type ConnectRequester struct {
	Dialer libconnect.Dialer
}

func (c ConnectRequester) Status(ctx context.Context, req emptypb.Empty, dst net.Addr,
) (hbirdv1.StatusResponse, error) {

	//fmt.Println("Connect status calling")
	peer := make(chan net.Addr, 1)
	dialer := c.Dialer(
		dst,
		squic.WithPeerChannel(peer),
		squic.WithDialTimeout(20*time.Second),
	)
	client := hbirdv1connect.NewHBirdServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(dst),
	)
	//fmt.Println("ConnectRequester Status dst", dst.(*snet.UDPAddr).String())
	resp, err := client.Status(ctx, connect.NewRequest(&req))
	if err != nil {
		return hbirdv1.StatusResponse{}, err
	}
	return *resp.Msg, err
}

type GrpcRequester struct {
	// Dialer dials a new gRPC connection.
	Dialer libgrpc.Dialer
}

func (g GrpcRequester) Status(ctx context.Context, req emptypb.Empty, dst net.Addr,
) (hbirdv1.StatusResponse, error) {
	fmt.Println("Grpc status calling")
	dialCtx, cancelF := context.WithTimeout(ctx, 20*time.Second)
	defer cancelF()
	fmt.Println("GrpcRequester Status dst", dst.(*snet.UDPAddr).String(), dst.String())
	conn, err := g.Dialer.Dial(dialCtx, dst)
	if err != nil {
		return hbirdv1.StatusResponse{}, err
	}
	defer conn.Close()

	var segPeer peer.Peer
	client := hbirdv1.NewHBirdServiceClient(conn)
	resp, err := client.Status(ctx,
		&req,
		libgrpc.RetryOption,
		grpc.Peer(&segPeer),
	)
	if err != nil {
		return hbirdv1.StatusResponse{}, err
	}
	return *resp, err
}

// RPC is used to fetch segments from a remote.
type RPC interface {
	Status(ctx context.Context, req emptypb.Empty, dst net.Addr) (hbirdv1.StatusResponse, error)
}

func (f *Requester) Status(
	ctx context.Context,
	req emptypb.Empty,
	server net.Addr,
) (hbirdv1.StatusResponse, error) {

	hconfig := happy.Config{}
	// specifically use only one rpc method for testing
	if ctx.Value("rpc") != nil && ctx.Value("rpc").(string) != "" {
		rpcType := ctx.Value("rpc").(string)
		if rpcType == "grpc" {
			hconfig = happy.Config{NoPreferred: true, NoFallback: false}
		} else if rpcType == "connectrpc" {
			hconfig = happy.Config{NoPreferred: false, NoFallback: true}
		}
	}
	resp, err := happy.Happy(
		ctx,
		happy.Call2[emptypb.Empty, net.Addr, hbirdv1.StatusResponse]{
			Call:   f.Connect.Status,
			Input1: req,
			Input2: server,
			Typ:    "proto.hbird.v1.HBirdService.Status",
		},
		happy.Call2[emptypb.Empty, net.Addr, hbirdv1.StatusResponse]{
			Call:   f.Grpc.Status,
			Input1: req,
			Input2: server,
			Typ:    "proto.hbird.v1.HBirdService.Status",
		},
		hconfig,
	)
	return resp, err
}

// findCsIpAddr finds the IP address of the CS inside the dstIA, using discovery information of
// the meta-information of the path.
func findCsIpAddr(p snet.Path, dstIA addr.IA) (netip.AddrPort, error) {
	v, ok := p.Metadata().DiscoveryInformation[dstIA]
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("no discovery information found for IA %s", dstIA)
	}
	if len(v.ControlServices) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no control service discovery info for IA %s", dstIA)
	}
	return v.ControlServices[0], nil
}

// passThroughRewriter is a noop rewriter, just returns the same address it was passed.
type passThroughRewriter struct{}

func (passThroughRewriter) RedirectToQUIC(_ context.Context, address net.Addr) (net.Addr, error) {
	return address, nil
}
