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

package path

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	connectrpc "connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

const (
	defaultFlyoverBW              = 64
	defaultFlyoverDurationSeconds = 10
	defaultRedemptionPort         = 30258
	defaultTokenSize              = 16
	defaultSciondAddress          = "127.0.0.1:30255"
)

// The client key is not checked for now. Remove this after it does.
// TODO deleteme.
const temporaryRedemptionClientPublicKeyBase64 = "MIGJAoGBALXNvQMtN+YUVxlF3lEWj9IRWE" +
	"Yy474ouB7EJ6JUkzGdu9+QThypHfOnZaxO4bbgD3sl5UCKCXDgW8MD1fuQoKNEVqbglVirdEAns1wJ" +
	"fqV5UP99qxGV2IwgS6ij2hrx6C7+lztL+a7yGNyDWTEnMljPtgSUDgk06kk21vZt5ZOhAgMBAAE="

// TODO deleteme same as above
var temporaryRedemptionClientKey = mustDecodeBase64(temporaryRedemptionClientPublicKeyBase64)

// RedeemFlyovers redeems flyovers for on-path ASes using redemption servers.
func (r *Reservation) RedeemFlyovers(ctx context.Context) error {
	baseHops := InterfacesToBaseHops(r.metadata.Interfaces)
	hfIndices := reservationHopFieldIndicesForFlyovers(r.Dec)
	if len(baseHops) != len(hfIndices) {
		return serrors.New("inconsistent reservation with path metadata",
			"base_hops", len(baseHops), "hop_fields", len(hfIndices))
	}

	cfg := r.redemption.clone()
	if cfg.StartTime == 0 {
		cfg.StartTime = uint32(r.Now().Unix())
	}
	if cfg.Bandwidth == 0 {
		cfg.Bandwidth = defaultFlyoverBW
	}
	if cfg.Duration == 0 {
		cfg.Duration = defaultFlyoverDurationSeconds
	}
	if cfg.Port == 0 {
		cfg.Port = defaultRedemptionPort
	}
	if cfg.lookup == nil {
		cfg.lookup = defaultFlyoverPathLookup(nil, cfg.daemonAddr)
	}
	if cfg.requester == nil {
		if cfg.dialer == nil {
			dialer, err := cfg.dialerFactory(ctx, cfg.daemonAddr)
			if err != nil {
				return serrors.Wrap("building default redemption dialer", err)
			}
			cfg.dialer = dialer
		}
		cfg.requester = NewConnectFlyoverRedemptionRequester(cfg.dialer)
	}
	if cfg.requester == nil {
		return serrors.New("missing redemption requester")
	}

	flyovers, err := getFlyoversForBaseHopsWithRedemption(ctx, r.metadata, baseHops, cfg)
	for i, hop := range baseHops {
		if flyover, ok := flyovers[hop]; ok {
			r.SetFlyover(hfIndices[i], flyover)
			continue
		}
		r.SetFlyover(hfIndices[i], &FlyoverData{BaseHop: hop, IsFlyover: false})
	}
	return err
}

// WithRedemptionRequester configures the reservation-level redemption requester.
func WithRedemptionRequester(requester FlyoverRedemptionRequester) ReservationModFcn {
	return func(r *Reservation) error {
		r.redemption.requester = requester
		return nil
	}
}

// WithRedemptionPathLookup configures reservation-level lookup logic.
func WithRedemptionPathLookup(
	lookup func(context.Context, addr.IA) (snet.Path, error),
) ReservationModFcn {
	return func(r *Reservation) error {
		r.redemption.lookup = lookup
		return nil
	}
}

// WithRedemptionDaemonAddress sets the daemon address used for default path lookup/runtime.
func WithRedemptionDaemonAddress(addr string) ReservationModFcn {
	return func(r *Reservation) error {
		r.redemption.daemonAddr = addr
		return nil
	}
}

// WithRedemptionDialer configures reservation-level connectrpc dialer.
func WithRedemptionDialer(dialer libconnect.Dialer) ReservationModFcn {
	return func(r *Reservation) error {
		r.redemption.dialer = dialer
		return nil
	}
}

// WithRedemptionOptions applies flyover redemption options at reservation construction time.
func WithRedemptionOptions(opts ...FlyoverRedemptionOption) ReservationModFcn {
	return func(r *Reservation) error {
		for _, opt := range opts {
			opt(&r.redemption)
		}
		return nil
	}
}

// GetFlyoversForPathWithRedemption obtains flyovers from real redemption servers.
// TODO this should be a function of Reservation, not standalone.
func GetFlyoversForPathWithRedemption(
	ctx context.Context,
	conn FlyoverPathResolver,
	p snet.Path,
	opts ...FlyoverRedemptionOption,
) (FlyoverMap, error) {
	meta := p.Metadata()
	if meta == nil {
		return nil, serrors.New("missing path metadata")
	}
	baseHops := InterfacesToBaseHops(meta.Interfaces)
	if len(baseHops) == 0 {
		return FlyoverMap{}, nil
	}
	if len(meta.Notes) != len(baseHops) {
		return nil, serrors.New("inconsistent path metadata",
			"base_hops", len(baseHops), "notes", len(meta.Notes))
	}

	cfg := newFlyoverRedemptionConfig(uint32(time.Now().Unix()), 0, conn)
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.lookup == nil {
		cfg.lookup = defaultFlyoverPathLookup(conn, cfg.daemonAddr)
	}
	if cfg.requester == nil {
		if cfg.dialer == nil {
			dialer, err := cfg.dialerFactory(ctx, cfg.daemonAddr)
			if err != nil {
				return nil, serrors.Wrap("building default redemption dialer", err)
			}
			cfg.dialer = dialer
		}
		cfg.requester = NewConnectFlyoverRedemptionRequester(cfg.dialer)
	}
	if cfg.requester == nil {
		return nil, serrors.New("missing redemption requester")
	}
	return getFlyoversForBaseHopsWithRedemption(ctx, meta, baseHops, cfg)
}

// FlyoverRedemptionRequester is used to redeem flyovers at remote ASes.
type FlyoverRedemptionRequester interface {
	Redeem(ctx context.Context, dst net.Addr, req *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error)
}

type connectFlyoverRequester struct {
	Dialer libconnect.Dialer
}

func (c connectFlyoverRequester) Redeem(
	ctx context.Context,
	dst net.Addr,
	req *hbirdv1.RedemptionRequests,
) (*hbirdv1.RedemptionResponses, error) {
	if c.Dialer == nil {
		return nil, serrors.New("missing connect dialer")
	}
	peer := make(chan net.Addr, 1)
	dialer := c.Dialer(
		dst,
		squic.WithPeerChannel(peer),
		squic.WithDialTimeout(20*time.Second),
	)
	client := hbirdv1connect.NewHBirdServiceClient(
		libconnect.HTTPClient{RoundTripper: &http3.Transport{Dial: dialer.DialEarly}},
		libconnect.BaseUrl(dst),
	)
	resp, err := client.Redeem(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// NewConnectFlyoverRedemptionRequester builds a connectrpc redemption requester.
func NewConnectFlyoverRedemptionRequester(dialer libconnect.Dialer) FlyoverRedemptionRequester {
	return connectFlyoverRequester{Dialer: dialer}
}

type flyoverPathLookup func(context.Context, addr.IA) (snet.Path, error)

// FlyoverPathResolver resolves paths to remote ASes for redemption requests.
type FlyoverPathResolver interface {
	Paths(ctx context.Context, dst, src addr.IA, f daemontypes.PathReqFlags) ([]snet.Path, error)
}

type RedemptionConfig struct {
	ClientKey     []byte
	StartTime     uint32
	Bandwidth     uint16
	Duration      uint16
	Port          uint16
	requester     FlyoverRedemptionRequester
	lookup        flyoverPathLookup
	daemonAddr    string
	dialer        libconnect.Dialer
	dialerFactory func(context.Context, string) (libconnect.Dialer, error)
}

func (c RedemptionConfig) clone() RedemptionConfig {
	c.ClientKey = append([]byte(nil), c.ClientKey...)
	return c
}

type FlyoverRedemptionOption func(*RedemptionConfig)

func WithFlyoverRedemptionRequester(requester FlyoverRedemptionRequester) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.requester = requester
	}
}

func WithFlyoverPathLookup(
	lookup func(context.Context, addr.IA) (snet.Path, error),
) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.lookup = lookup
	}
}

func WithFlyoverClientKey(clientKey []byte) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.ClientKey = append([]byte(nil), clientKey...)
	}
}

func WithFlyoverStartTime(startTime uint32) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.StartTime = startTime
	}
}

func WithFlyoverBandwidth(bw uint16) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.Bandwidth = bw
	}
}

func WithFlyoverDuration(duration uint16) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.Duration = duration
	}
}

func WithFlyoverRedemptionPort(port uint16) FlyoverRedemptionOption {
	return func(c *RedemptionConfig) {
		c.Port = port
	}
}

func newFlyoverRedemptionConfig(
	startTime uint32,
	minBW uint16,
	conn FlyoverPathResolver,
) RedemptionConfig {
	daemonAddr := os.Getenv("SCION_DAEMON")
	if daemonAddr == "" {
		daemonAddr = defaultSciondAddress
	}
	bw := minBW
	if bw == 0 {
		bw = defaultFlyoverBW
	}
	return RedemptionConfig{
		lookup:        defaultFlyoverPathLookup(conn, daemonAddr),
		daemonAddr:    daemonAddr,
		dialerFactory: defaultConnectDialerFactory,
		ClientKey:     append([]byte(nil), temporaryRedemptionClientKey...),
		StartTime:     startTime,
		Bandwidth:     bw,
		Duration:      defaultFlyoverDurationSeconds,
		Port:          defaultRedemptionPort,
	}
}

func defaultFlyoverPathLookup(conn FlyoverPathResolver, daemonAddr string) flyoverPathLookup {
	if conn != nil {
		return func(ctx context.Context, dst addr.IA) (snet.Path, error) {
			paths, err := conn.Paths(ctx, dst, 0, daemontypes.PathReqFlags{})
			if err != nil {
				return nil, err
			}
			if len(paths) == 0 {
				return nil, serrors.New("no path available", "dst", dst)
			}
			return paths[0], nil
		}
	}
	return func(ctx context.Context, dst addr.IA) (snet.Path, error) {
		paths, err := lookupPathsViaSciond(ctx, daemonAddr, dst, 0, daemontypes.PathReqFlags{})
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return nil, serrors.New("no path available", "dst", dst)
		}
		return paths[0], nil
	}
}

type passThroughRewriter struct{}

func (passThroughRewriter) RedirectToQUIC(_ context.Context, address net.Addr) (net.Addr, error) {
	return address, nil
}

func defaultConnectDialerFactory(ctx context.Context, daemonAddr string) (libconnect.Dialer, error) {
	localIA, startPort, endPort, ifaces, err := localTopologyFromSciond(ctx, daemonAddr)
	if err != nil {
		return nil, err
	}
	localIP, err := firstLocalIP(ifaces)
	if err != nil {
		return nil, err
	}

	network := &snet.SCIONNetwork{
		Topology: snet.Topology{
			LocalIA: localIA,
			PortRange: snet.TopologyPortRange{
				Start: startPort,
				End:   endPort,
			},
			Interface: func(id uint16) (netip.AddrPort, bool) {
				a, ok := ifaces[id]
				return a, ok
			},
		},
	}
	client, err := network.Listen(ctx, "udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		return nil, serrors.Wrap("opening local SCION socket for redemption", err)
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	factory := squic.EarlyDialerFactory{
		Transport: &quic.Transport{Conn: client},
		TLSConfig: tlsConf,
		Rewriter:  passThroughRewriter{},
	}
	return factory.NewDialer, nil
}

func firstLocalIP(ifaces map[uint16]netip.AddrPort) (net.IP, error) {
	if len(ifaces) == 0 {
		return nil, serrors.New("no local interfaces from daemon")
	}
	keys := make([]int, 0, len(ifaces))
	for id := range ifaces {
		keys = append(keys, int(id))
	}
	sort.Ints(keys)
	for _, id := range keys {
		a := ifaces[uint16(id)]
		if !a.Addr().IsValid() || a.Addr().IsUnspecified() {
			continue
		}
		return a.Addr().AsSlice(), nil
	}
	for _, id := range keys {
		a := ifaces[uint16(id)]
		if a.Addr().IsValid() {
			return a.Addr().AsSlice(), nil
		}
	}
	return nil, serrors.New("could not derive local IP from daemon interfaces")
}

func localTopologyFromSciond(
	ctx context.Context,
	daemonAddr string,
) (addr.IA, uint16, uint16, map[uint16]netip.AddrPort, error) {
	conn, err := grpc.NewClient(daemonAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return 0, 0, 0, nil, serrors.Wrap("connecting to daemon", err, "daemon", daemonAddr)
	}
	defer conn.Close()
	client := sdpb.NewDaemonServiceClient(conn)

	asResp, err := client.AS(ctx, &sdpb.ASRequest{})
	if err != nil {
		return 0, 0, 0, nil, serrors.Wrap("querying local IA from daemon", err)
	}
	portResp, err := client.PortRange(ctx, &emptypb.Empty{})
	if err != nil {
		return 0, 0, 0, nil, serrors.Wrap("querying daemon port range", err)
	}
	ifResp, err := client.Interfaces(ctx, &sdpb.InterfacesRequest{})
	if err != nil {
		return 0, 0, 0, nil, serrors.Wrap("querying daemon interfaces", err)
	}
	ifaces := make(map[uint16]netip.AddrPort, len(ifResp.Interfaces))
	for ifID, intf := range ifResp.Interfaces {
		a, err := netip.ParseAddrPort(intf.Address.Address)
		if err != nil {
			return 0, 0, 0, nil, serrors.Wrap("parsing daemon interface address", err,
				"address", intf.Address.Address)
		}
		ifaces[uint16(ifID)] = a
	}
	return addr.IA(asResp.IsdAs), uint16(portResp.DispatchedPortStart),
		uint16(portResp.DispatchedPortEnd), ifaces, nil
}

func lookupPathsViaSciond(
	ctx context.Context,
	daemonAddr string,
	dst, src addr.IA,
	flags daemontypes.PathReqFlags,
) ([]snet.Path, error) {
	conn, err := grpc.NewClient(daemonAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, serrors.Wrap("connecting to daemon", err, "daemon", daemonAddr)
	}
	defer conn.Close()

	client := sdpb.NewDaemonServiceClient(conn)
	resp, err := client.Paths(ctx, &sdpb.PathsRequest{
		SourceIsdAs:      uint64(src),
		DestinationIsdAs: uint64(dst),
		Hidden:           flags.Hidden,
		Refresh:          flags.Refresh,
	})
	if err != nil {
		return nil, err
	}
	paths := make([]snet.Path, 0, len(resp.Paths))
	for _, p := range resp.Paths {
		converted, err := convertDaemonPath(p, dst)
		if err != nil {
			return nil, err
		}
		paths = append(paths, converted)
	}
	return paths, nil
}

func convertDaemonPath(p *sdpb.Path, dst addr.IA) (Path, error) {
	expiry := time.Unix(p.Expiration.Seconds, int64(p.Expiration.Nanos))
	if len(p.Interfaces) == 0 {
		return Path{
			Src: dst,
			Dst: dst,
			Meta: snet.PathMetadata{
				MTU:    uint16(p.Mtu),
				Expiry: expiry,
			},
			DataplanePath: Empty{},
		}, nil
	}
	underlay, err := net.ResolveUDPAddr("udp", p.Interface.Address.Address)
	if err != nil {
		return Path{}, serrors.Wrap("resolving underlay", err)
	}
	interfaces := make([]snet.PathInterface, len(p.Interfaces))
	for i, pi := range p.Interfaces {
		interfaces[i] = snet.PathInterface{
			ID: iface.ID(pi.Id),
			IA: addr.IA(pi.IsdAs),
		}
	}
	latency := make([]time.Duration, len(p.Latency))
	for i, v := range p.Latency {
		latency[i] = time.Second*time.Duration(v.Seconds) + time.Duration(v.Nanos)
	}
	geo := make([]snet.GeoCoordinates, len(p.Geo))
	for i, v := range p.Geo {
		geo[i] = snet.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]snet.LinkType, len(p.LinkType))
	for i, v := range p.LinkType {
		linkType[i] = linkTypeFromPB(v)
	}
	res := Path{
		Src: interfaces[0].IA,
		Dst: dst,
		DataplanePath: SCION{
			Raw: p.Raw,
		},
		NextHop: underlay,
		Meta: snet.PathMetadata{
			Interfaces:   interfaces,
			MTU:          uint16(p.Mtu),
			Expiry:       expiry,
			Latency:      latency,
			Bandwidth:    p.Bandwidth,
			Geo:          geo,
			LinkType:     linkType,
			InternalHops: p.InternalHops,
			Notes:        p.Notes,
		},
	}
	if p.DiscoveryInformation != nil {
		res.Meta.DiscoveryInformation = make(map[addr.IA]snet.DiscoveryInformation)
		for ia, di := range p.DiscoveryInformation {
			cses := make([]netip.AddrPort, 0, len(di.ControlServiceAddresses))
			dses := make([]netip.AddrPort, 0, len(di.DiscoveryServiceAddresses))
			for _, cs := range di.ControlServiceAddresses {
				ap, err := netip.ParseAddrPort(cs)
				if err != nil {
					return Path{}, serrors.Wrap("parsing control service address", err,
						"address", cs, "ia", ia)
				}
				cses = append(cses, ap)
			}
			for _, ds := range di.DiscoveryServiceAddresses {
				ap, err := netip.ParseAddrPort(ds)
				if err != nil {
					return Path{}, serrors.Wrap("parsing discovery service address", err,
						"address", ds, "ia", ia)
				}
				dses = append(dses, ap)
			}
			res.Meta.DiscoveryInformation[addr.IA(ia)] = snet.DiscoveryInformation{
				ControlServices:   cses,
				DiscoveryServices: dses,
			}
		}
	}
	if p.EpicAuths != nil {
		res.Meta.EpicAuths = snet.EpicAuths{
			AuthPHVF: append([]byte(nil), p.EpicAuths.AuthPhvf...),
			AuthLHVF: append([]byte(nil), p.EpicAuths.AuthLhvf...),
		}
	}
	return res, nil
}

func linkTypeFromPB(lt sdpb.LinkType) snet.LinkType {
	switch lt {
	case sdpb.LinkType_LINK_TYPE_DIRECT:
		return snet.LinkTypeDirect
	case sdpb.LinkType_LINK_TYPE_MULTI_HOP:
		return snet.LinkTypeMultihop
	case sdpb.LinkType_LINK_TYPE_OPEN_NET:
		return snet.LinkTypeOpennet
	default:
		return snet.LinkTypeUnset
	}
}

func supportsHumm(note string) bool {
	// The received JSON will have at least these fields:
	// "hummingbird-v0": {
	//     "supported": true
	// }
	type hummPayload struct {
		HummingbirdV0 *struct {
			Supported *bool `json:"supported"`
		} `json:"hummingbird-v0"`
	}
	var payload hummPayload
	if err := json.Unmarshal([]byte(note), &payload); err != nil {
		log.Debug("hummingbird Reservation: failed to parse hummingbird note",
			"note", note, "err", err)
		return false
	}
	return payload.HummingbirdV0 != nil &&
		payload.HummingbirdV0.Supported != nil &&
		*payload.HummingbirdV0.Supported
}

func getFlyoversForBaseHopsWithRedemption(
	ctx context.Context,
	meta *snet.PathMetadata,
	baseHops []BaseHop,
	cfg RedemptionConfig,
) (FlyoverMap, error) {
	if meta == nil {
		return nil, serrors.New("missing path metadata")
	}
	if len(meta.Notes) != len(baseHops) {
		return nil, serrors.New("inconsistent path metadata",
			"base_hops", len(baseHops), "notes", len(meta.Notes))
	}
	if cfg.lookup == nil {
		return nil, serrors.New("missing path lookup")
	}

	result := make(FlyoverMap, len(baseHops))
	for _, hop := range baseHops {
		result[hop] = &FlyoverData{BaseHop: hop, IsFlyover: false}
	}

	type candidate struct {
		idx int
		hop BaseHop
	}
	candidates := make([]candidate, 0, len(baseHops))
	for i, hop := range baseHops {
		if !supportsHumm(meta.Notes[i]) {
			continue
		}
		candidates = append(candidates, candidate{idx: i, hop: hop})
	}

	if len(candidates) == 0 {
		return result, nil
	}

	errMsgs := make([]error, len(candidates))
	results := make([]*FlyoverData, len(candidates))
	var wg sync.WaitGroup
	wg.Add(len(candidates))
	for i, c := range candidates {
		go func(i int, c candidate) {
			defer wg.Done()

			resolvedPath, err := cfg.lookup(ctx, c.hop.IA)
			if err != nil {
				errMsgs[i] = serrors.Wrap("path lookup failed", err, "ia", c.hop.IA)
				return
			}
			dst, err := redemptionServerAddress(resolvedPath, c.hop.IA, cfg.Port)
			if err != nil {
				errMsgs[i] = serrors.Wrap("endpoint resolution failed", err, "ia", c.hop.IA)
				return
			}

			redeemReq := &hbirdv1.RedemptionRequests{
				Redemption: []*hbirdv1.RedemptionRequest{
					{
						RedInfo: &hbirdv1.RedemptionInfo{
							Ingress:   uint32(c.hop.Ingress),
							Egress:    uint32(c.hop.Egress),
							Bw:        uint32(cfg.Bandwidth),
							StartTime: cfg.StartTime,
							Duration:  uint32(cfg.Duration),
						},
						IngressToken: make([]byte, defaultTokenSize),
						EgressToken:  make([]byte, defaultTokenSize),
					},
				},
				ClientKey: cfg.ClientKey,
			}
			resp, err := cfg.requester.Redeem(ctx, dst, redeemReq)
			if err != nil {
				errMsgs[i] = serrors.Wrap("redeem failed", err, "ia", c.hop.IA)
				return
			}
			if len(resp.Reservation) == 0 {
				errMsgs[i] = serrors.New("redeem returned no reservation", "ia", c.hop.IA)
				return
			}

			flyover, err := reservationToFlyover(
				c.hop,
				resp.Reservation[0],
				cfg.Bandwidth,
				cfg.StartTime,
				cfg.Duration)
			if err != nil {
				errMsgs[i] = serrors.Wrap("redeem response decode failed", err, "ia", c.hop.IA)
				return
			}

			results[i] = flyover
		}(i, c)
	}
	wg.Wait()

	var errs serrors.List
	for i, c := range candidates {
		if errMsgs[i] != nil {
			errs = append(errs, errMsgs[i])
		}
		if results[i] != nil {
			result[c.hop] = results[i]
		}
	}

	return result, errs.ToError()
}

func reservationToFlyover(
	hop BaseHop,
	reservation *hbirdv1.Reservation,
	bw uint16,
	startTime uint32,
	duration uint16,
) (*FlyoverData, error) {
	if reservation == nil {
		return nil, serrors.New("missing reservation")
	}
	if len(reservation.AuthKey) < 16 {
		return nil, serrors.New("reservation auth key too short", "len", len(reservation.AuthKey))
	}
	var ak [16]byte
	copy(ak[:], reservation.AuthKey[:16])
	return &FlyoverData{
		BaseHop:   hop,
		IsFlyover: true,
		ResID:     reservation.ResId,
		Ak:        ak,
		Bw:        bw,
		StartTime: startTime,
		Duration:  duration,
	}, nil
}

func redemptionServerAddress(p snet.Path, targetIA addr.IA, port uint16) (*snet.UDPAddr, error) {
	meta := p.Metadata()
	if meta == nil {
		return nil, serrors.New("path metadata missing")
	}
	disco, ok := meta.DiscoveryInformation[targetIA]
	if !ok {
		return nil, serrors.New("missing discovery information", "ia", targetIA)
	}
	if len(disco.ControlServices) == 0 {
		return nil, serrors.New("missing control service entries", "ia", targetIA)
	}
	nextHop := p.UnderlayNextHop()
	if nextHop == nil {
		return nil, serrors.New("missing next hop", "ia", targetIA)
	}
	cs := disco.ControlServices[0]
	return &snet.UDPAddr{
		IA:      targetIA,
		Path:    p.Dataplane(),
		NextHop: nextHop,
		Host: &net.UDPAddr{
			IP:   cs.Addr().AsSlice(),
			Port: int(port),
		},
	}, nil
}

func mustDecodeBase64(data string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded base64 data: %v", err))
	}
	return decoded
}
