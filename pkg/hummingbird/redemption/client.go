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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/serrors"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
)

const RedemptionServerPort = 30258

type RedemptionClient struct {
	LocaIA     addr.IA
	SdConn     daemon.Connector // Daemon connector for paths.
	requestMap map[addr.IA]hummingbird.RedemptionRequest

	intraAsClientFactory func() hbirdv1connect.HBirdServiceClient
	interAsClientFactory func(
		ctx context.Context,
		dst *snet.UDPAddr,
	) hbirdv1connect.HBirdServiceClient

	pubBytes []byte
	privKey  *rsa.PrivateKey
}

func NewRedemptionClient(ctx context.Context, sdConn daemon.Connector) (*RedemptionClient, error) {
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, err
	}

	// Build the client factories.
	// Intra-AS.
	intraAsClientFactory, err := buildIntraAsFactory(ctx, sdConn)
	if err != nil {
		return nil, err
	}

	// Inter-AS.
	interAsClientFactory, err := buildInterAsFactory(ctx, sdConn)
	if err != nil {
		return nil, err
	}

	pubBytes, privKey, err := createPublicPrivateKeys()
	if err != nil {
		return nil, err
	}

	return &RedemptionClient{
		LocaIA: localIA,
		SdConn: sdConn,

		requestMap:           make(map[addr.IA]hummingbird.RedemptionRequest),
		intraAsClientFactory: intraAsClientFactory,
		interAsClientFactory: interAsClientFactory,

		pubBytes: pubBytes,
		privKey:  privKey,
	}, nil
}

func (c *RedemptionClient) SetRequestData(ia addr.IA, req hummingbird.RedemptionRequest) {
	c.requestMap[ia] = req
}

// RedeemHop redeems one hop.
func (c RedemptionClient) RedeemHop(
	ctx context.Context,
	ia addr.IA,
) (*hummingbird.FlyoverData, error) {
	// Do we have a request for this particular IA?
	request, ok := c.requestMap[ia]
	if !ok {
		// No request data for this hop, do nothing.
		return nil, nil
	}

	client, err := c.clientForAs(ctx, ia)
	if err != nil {
		return nil, err
	}

	return c.redeemHop(ctx, ia, client, request)
}

func (c RedemptionClient) RedeemPath(
	ctx context.Context,
	p snet.Path,
) ([]*hummingbird.FlyoverData, error) {
	if p.Source() != c.LocaIA {
		return nil, fmt.Errorf("path starts at %s, expected local IA to be %s",
			p.Source(), c.LocaIA)
	}
	if p.Metadata() == nil {
		return nil, fmt.Errorf("requested path does not have metadata")
	}

	ifaces := p.Metadata().Interfaces
	numHops := len(ifaces)/2 + 1
	hops := make([]addr.IA, numHops)

	// First hop.
	hops[0] = ifaces[0].IA
	// Rest of hops.
	for i := 1; i < numHops; i++ {
		hops[i] = ifaces[i+2-1].IA
	}

	results := make([]*hummingbird.FlyoverData, len(hops))
	failures := make([]error, len(hops))
	wg := sync.WaitGroup{}
	wg.Add(len(hops))
	for i := range hops {
		go func(i int) {
			defer wg.Done()

			// Find a request.
			request, ok := c.requestMap[hops[i]]
			if !ok {
				// No request: do nothing.
				return
			}
			// Get a client.
			client, err := c.clientForAs(ctx, hops[i])
			if err != nil {
				failures[i] = fmt.Errorf("getting client for %s: %w", hops[i], err)
				return
			}
			results[i], failures[i] = c.redeemHop(ctx, hops[i], client, request)
		}(i)
	}
	wg.Wait()

	return results, errors.Join(failures...)
}

func (c RedemptionClient) redeemHop(
	ctx context.Context,
	ia addr.IA,
	client hbirdv1connect.HBirdServiceClient,
	request hummingbird.RedemptionRequest,
) (*hummingbird.FlyoverData, error) {
	pbRequest := &hbirdv1.RedemptionRequests{
		Redemption: []*hbirdv1.RedemptionRequest{
			&hbirdv1.RedemptionRequest{
				RedInfo: &hbirdv1.RedemptionInfo{
					Ingress:   uint32(request.Ingress),
					Egress:    uint32(request.Egress),
					Bw:        uint32(request.BW),
					StartTime: request.StartTime,
					Duration:  uint32(request.Duration),
				},
				IngressToken: request.IngressToken,
				EgressToken:  request.EgressToken,
			},
		},
		ClientKey: c.pubBytes,
	}
	if len(request.ClientKey) > 0 {
		pbRequest.ClientKey = request.ClientKey
	}
	res, err := client.Redeem(ctx, connect.NewRequest(pbRequest))
	if err != nil {
		return nil, fmt.Errorf("redeem call failed: %w", err)
	}
	if res == nil || res.Msg == nil {
		return nil, serrors.New("redemption response is nil")
	}
	if len(res.Msg.Reservation) == 0 {
		return nil, serrors.New("redemption call returned no flyovers")
	}
	resp := res.Msg.Reservation[0]

	ak, err := c.decryptAk(resp.AuthKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting Ak: %w", err)
	}
	if len(ak) != hummingbird.AkSize {
		return nil, fmt.Errorf("redeemed key has wrong length %d", len(resp.AuthKey))
	}

	flyover := &hummingbird.FlyoverData{
		BaseHop: hummingbird.BaseHop{
			IA:      ia,
			Ingress: request.Ingress,
			Egress:  request.Egress,
		},
		ResID:     resp.ResId,
		Ak:        [hummingbird.AkSize]byte(ak),
		Bw:        request.BW,
		StartTime: request.StartTime,
		Duration:  request.Duration,
	}
	return flyover, nil
}

func (c RedemptionClient) clientForAs(
	ctx context.Context,
	ia addr.IA,
) (hbirdv1connect.HBirdServiceClient, error) {
	// Is this hop the local IA?
	var client hbirdv1connect.HBirdServiceClient
	if ia == c.LocaIA {
		// It is local. Use the intra-AS client.
		client = c.intraAsClientFactory()
	} else {
		// Non local, use the inter-AS client.
		dstAddr, err := c.getDstAddr(ctx, ia)
		if err != nil {
			return nil, fmt.Errorf("finding the CS address of on-path AS %s: %w", ia, err)
		}
		client = c.interAsClientFactory(ctx, dstAddr)
	}
	return client, nil
}

func (c RedemptionClient) decryptAk(encryptedAk []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, encryptedAk, nil)
}

func (c RedemptionClient) getDstAddr(ctx context.Context, dstIa addr.IA) (*snet.UDPAddr, error) {
	// Find a path to ia.
	paths, err := c.SdConn.Paths(ctx, dstIa, c.LocaIA, types.PathReqFlags{})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, err
	}
	chosenPath := paths[0]

	// Find the CS address of the dstIA.
	ipAddr, err := findCsIpAddr(chosenPath, dstIa)
	if err != nil {
		return nil, err
	}
	return &snet.UDPAddr{
		IA: dstIa,
		Host: &net.UDPAddr{
			IP:   net.IP(ipAddr.Addr().AsSlice()),
			Port: RedemptionServerPort,
		},
		Path:    chosenPath.Dataplane(),
		NextHop: chosenPath.UnderlayNextHop(),
	}, nil
}

func buildIntraAsFactory(ctx context.Context, sdConn daemon.Connector,
) (func() hbirdv1connect.HBirdServiceClient, error) {
	topo := daemon.TopoQuerier{Connector: sdConn}
	csAddr, err := topo.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, fmt.Errorf("cannot find CS address: %w", err)
	}
	// Build the redemption server's address using the CS's one.
	dstRedemptionServer := fmt.Sprintf("http://%s:%d", csAddr.IP.String(), RedemptionServerPort)
	return func() hbirdv1connect.HBirdServiceClient {
		return hbirdv1connect.NewHBirdServiceClient(
			http.DefaultClient,
			dstRedemptionServer,
		)
	}, nil
}

func buildInterAsFactory(ctx context.Context, sdConn daemon.Connector,
) (func(
	ctx context.Context,
	dst *snet.UDPAddr,
) hbirdv1connect.HBirdServiceClient,
	error) {

	// Build SCION network:
	topo, err := daemon.LoadTopology(ctx, sdConn)
	if err != nil {
		return nil, fmt.Errorf("cannot load topology: %w", err)
	}

	scionNet := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
		},
		Topology: topo,
	}

	// Dialer factory.
	clientAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), // deleteme TODO is this correct?
	}
	client, err := scionNet.Listen(ctx, "udp", clientAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen in the SCION network with addr \"%s\":%w",
			clientAddr.String(), err)
	}

	insecureClientTlsConfig, err := appnet.GenerateTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot generate TLS configuration: %w", err)
	}
	insecureClientTlsConfig.InsecureSkipVerify = true
	insecureClientTlsConfig.NextProtos = []string{"SCION"}

	qConnDialer := &squic.ConnDialer{
		Transport: &quic.Transport{
			Conn: client,
		},
		TLSConfig: insecureClientTlsConfig,
	}

	dialerFactory := &squic.EarlyDialerFactory{
		Transport: qConnDialer.Transport,
		TLSConfig: libconnect.AdaptClientTLS(qConnDialer.TLSConfig),
		Rewriter:  passThroughRewriter{},
	}

	return func(
		ctx context.Context,
		dstAddr *snet.UDPAddr,
	) hbirdv1connect.HBirdServiceClient {
		var timeout = 3 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		readyDialer := dialerFactory.NewDialer(dstAddr, squic.WithDialTimeout(timeout))
		return hbirdv1connect.NewHBirdServiceClient(
			libconnect.HTTPClient{
				RoundTripper: &http3.Transport{
					Dial: readyDialer.DialEarly,
				},
			},
			libconnect.BaseUrl(dstAddr),
		)
	}, nil
}

func createPublicPrivateKeys() ([]byte, *rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate RSA key: %w", err)
	}

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	return pubKeyBytes, privKey, nil
}

type passThroughRewriter struct{}

func (passThroughRewriter) RedirectToQUIC(_ context.Context, address net.Addr) (net.Addr, error) {
	return address, nil
}

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
