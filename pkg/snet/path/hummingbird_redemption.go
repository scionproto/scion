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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	connectrpc "connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	hbirdv1connect "github.com/scionproto/scion/pkg/proto/hbird/v1/hbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
)

const (
	defaultFlyoverBW              = 64
	defaultFlyoverDurationSeconds = 10
	defaultRedemptionPort         = 30258
	defaultTokenSize              = 16
)

// The client key is not checked for now. Remove this after it does.
const temporaryRedemptionClientPublicKeyBase64 = "MIGJAoGBALXNvQMtN+YUVxlF3lEWj9IRWE" +
	"Yy474ouB7EJ6JUkzGdu9+QThypHfOnZaxO4bbgD3sl5UCKCXDgW8MD1fuQoKNEVqbglVirdEAns1wJ" +
	"fqV5UP99qxGV2IwgS6ij2hrx6C7+lztL+a7yGNyDWTEnMljPtgSUDgk06kk21vZt5ZOhAgMBAAE="

var temporaryRedemptionClientKey = mustDecodeBase64(temporaryRedemptionClientPublicKeyBase64)

// RedeemFlyovers redeems flyovers for on-path ASes using redemption servers.
func (r *Reservation) RedeemFlyovers(
	ctx context.Context,
	conn FlyoverPathResolver,
	opts ...FlyoverRedemptionOption,
) error {
	if r.metadata == nil {
		return serrors.New("missing path metadata")
	}
	baseHops := InterfacesToBaseHops(r.metadata.Interfaces)
	hfIndices := reservationHopFieldIndicesForFlyovers(r.Dec)
	if len(baseHops) != len(hfIndices) {
		return serrors.New("inconsistent reservation with path metadata",
			"base_hops", len(baseHops), "hop_fields", len(hfIndices))
	}

	cfg := newFlyoverRedemptionConfig(uint32(r.Now.Unix()), r.MinBW, conn)
	for _, opt := range opts {
		opt(&cfg)
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

type flyoverRedemptionConfig struct {
	requester FlyoverRedemptionRequester
	lookup    flyoverPathLookup
	clientKey []byte
	startTime uint32
	bandwidth uint16
	duration  uint16
	port      uint16
}

type FlyoverRedemptionOption func(*flyoverRedemptionConfig)

func WithFlyoverRedemptionRequester(requester FlyoverRedemptionRequester) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.requester = requester
	}
}

func WithFlyoverPathLookup(
	lookup func(context.Context, addr.IA) (snet.Path, error),
) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.lookup = lookup
	}
}

func WithFlyoverClientKey(clientKey []byte) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.clientKey = append([]byte(nil), clientKey...)
	}
}

func WithFlyoverStartTime(startTime uint32) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.startTime = startTime
	}
}

func WithFlyoverBandwidth(bw uint16) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.bandwidth = bw
	}
}

func WithFlyoverDuration(duration uint16) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.duration = duration
	}
}

func WithFlyoverRedemptionPort(port uint16) FlyoverRedemptionOption {
	return func(c *flyoverRedemptionConfig) {
		c.port = port
	}
}

func newFlyoverRedemptionConfig(
	startTime uint32,
	minBW uint16,
	conn FlyoverPathResolver,
) flyoverRedemptionConfig {
	bw := minBW
	if bw == 0 {
		bw = defaultFlyoverBW
	}
	return flyoverRedemptionConfig{
		lookup:    defaultFlyoverPathLookup(conn),
		clientKey: append([]byte(nil), temporaryRedemptionClientKey...),
		startTime: startTime,
		bandwidth: bw,
		duration:  defaultFlyoverDurationSeconds,
		port:      defaultRedemptionPort,
	}
}

func defaultFlyoverPathLookup(conn FlyoverPathResolver) flyoverPathLookup {
	if conn == nil {
		return nil
	}
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
	cfg flyoverRedemptionConfig,
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
			dst, err := redemptionServerAddress(resolvedPath, c.hop.IA, cfg.port)
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
							Bw:        uint32(cfg.bandwidth),
							StartTime: cfg.startTime,
							Duration:  uint32(cfg.duration),
						},
						IngressToken: make([]byte, defaultTokenSize),
						EgressToken:  make([]byte, defaultTokenSize),
					},
				},
				ClientKey: cfg.clientKey,
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
				cfg.bandwidth,
				cfg.startTime,
				cfg.duration)
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
