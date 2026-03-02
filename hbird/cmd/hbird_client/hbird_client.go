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
	emptypb "github.com/golang/protobuf/ptypes/empty"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/daemon"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/svc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/connect/happy"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	//slog "github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/topology"

	//hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
)

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
	if !skipIP {
		client := hbirdv1connect.NewHBirdServiceClient(
			http.DefaultClient,
			"http://localhost:30258",
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

	testSCION(remoteAS, rpcType)
}

func testSCION(remoteAS, rpcType string) {
	ctx := context.Background()
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:   "/etc/scion/topology.json",
		Reload: app.SIGHUPChannel(ctx),
	})
	if err != nil {
		fmt.Println("Error creating topology loader", err)
		return
	}

	clientNet := &snet.SCIONNetwork{
		Topology: func(topo *topology.Loader) snet.Topology {
			start, end := topo.PortRange()
			return snet.Topology{
				LocalIA: topo.IA(),
				PortRange: snet.TopologyPortRange{
					Start: start,
					End:   end,
				},
				Interface: func(ifID uint16) (netip.AddrPort, bool) {
					a := topo.UnderlayNextHop(ifID)
					if a == nil {
						return netip.AddrPort{}, false
					}
					return a.AddrPort(), true
				},
			}
		}(topo),
	}
	clientAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	}
	rewriter := &appnet.AddressRewriter{
		Router: &snet.BaseRouter{
			Querier: appnet.IntraASPathQuerier{
				IA:  topo.IA(),
				MTU: topo.MTU()}},
		SVCRouter: topo,
		Resolver: &svc.Resolver{
			LocalIA: topo.IA(),
			Network: &snet.SCIONNetwork{
				Topology:    clientNet.Topology,
				SCMPHandler: nil,
			},
			LocalIP: clientAddr.IP,
		},
	}
	client, err := clientNet.Listen(ctx, "udp", clientAddr)
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

	destAddr := clientAddr
	destAddr.Port = 30258
	var destSAddr *snet.UDPAddr
	destSAddr, err = snet.ParseUDPAddr(remoteAS + "," + destAddr.String())
	if err != nil {
		fmt.Println("Error parsing destination address", err)
	}

	var envFlags flag.SCIONEnvironment
	daemonAddr := envFlags.Daemon()
	sd, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		fmt.Println("connecting to SCION Daemon", err)
		return
	}
	defer sd.Close()
	opts := []path.Option{
		path.WithInteractive(false),
		//path.WithRefresh(true),
		path.WithSequence("0* 71-1916#3 0*"),
		/*path.WithProbing(&path.ProbeConfig{
			LocalIA: topo.IA(),
			LocalIP: clientAddr.IP,
		}),*/
	}
	path, err := path.Choose(context.TODO(), sd, destSAddr.IA, opts...)
	if err != nil {
		fmt.Println(err)
		return
	}
	//fmt.Println("control plane path:", path)
	destSAddr.Path = path.Dataplane()
	destSAddr.NextHop = path.UnderlayNextHop()
	//fmt.Println("dataplane path:", destSAddr.Path)

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

func (f *Requester) Status(ctx context.Context, req emptypb.Empty,
	server net.Addr) (hbirdv1.StatusResponse, error) {

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
