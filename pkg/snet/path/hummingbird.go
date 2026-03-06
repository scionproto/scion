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
	"encoding/binary"
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
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
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

// Reservation is the snet path for a Reservation path type.
// When creating a packet with a Reservation path, the flyover fields must contain the MAC that
// was computed using the correct payload size.
// This path represents a possibly partially reserved path, with zero or more flyovers.
type Reservation struct {
	DstIA    addr.IA            // Destination IA of the path.
	Dec      *dphum.Decoded     // The Hummingbird path.
	metadata *snet.PathMetadata // Set at construction time.
	Hops     []*FlyoverData     // Same length as `Dec`. Hops[i]==nil iff no flyover at i.
	Now      time.Time          // The current time.
	MinBW    uint16             // The minimum required bandwidth for the flyovers.

	counter uint32 // duplicate detection counter
}

var _ snet.DataplanePath = (*Reservation)(nil)

// NewReservation builds a new Hummingbird Reservation based on the destination IA and the
// options passed.
func NewReservation(opts ...ReservationModFcn) (*Reservation, error) {
	r := &Reservation{
		Now: time.Now(),
		Dec: &dphum.Decoded{},
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(r); err != nil {
			return nil, err
		}
	}

	if len(r.Hops) != len(r.Dec.HopFields) {
		return nil, fmt.Errorf("wrong number of flyover hops %d, expected %d from path",
			len(r.Hops), len(r.Dec.HopFields))
	}

	if r.DstIA == 0 {
		return nil, serrors.New("unset destination IA")
	}

	return r, nil
}

// SetPath sets the path into the passed-by-pointer scion headers.
// When called, the scion layer has its fields (e.g. payload length, src IA, etc.) already set up.
func (r Reservation) SetPath(s *slayers.SCION) error {
	dec := r.DeriveDataPlanePath(s.PayloadLen, r.Now)
	s.Path, s.PathType = dec, dec.Type()
	return nil
}

// DeriveDataPlanePath sets pathmeta timestamps and increments duplicate detection counter and
// updates MACs of all flyoverfields.
func (r Reservation) DeriveDataPlanePath(
	pktLen uint16,
	timeStamp time.Time,
) *dphum.Decoded {

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	millis |= r.counter
	r.Dec.Base.PathMeta.BaseTS = secs
	r.Dec.Base.PathMeta.HighResTS = millis
	// increment counter for next packet
	r.counter++
	r.counter %= 1 << 22

	// compute Macs for Flyovers
	var byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	var xkbuffer [hummingbird.XkBufferSize]uint32
	for i, h := range r.Hops {
		if h == nil {
			continue
		}
		hf := &r.Dec.HopFields[i]
		hf.ResStartTime = uint16(secs - h.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(
			h.Ak[:],
			r.DstIA,
			pktLen,
			hf.ResStartTime,
			millis,
			byteBuffer[:],
			xkbuffer[:],
		)

		binary.BigEndian.PutUint32(hf.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(hf.HopField.Mac[:4]))
		binary.BigEndian.PutUint16(hf.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(hf.HopField.Mac[4:]))
	}
	return r.Dec
}

// ReservationModFcn is a options setting function for a reservation.
type ReservationModFcn func(*Reservation) error

// WithNow modifies the current point in time for this reservation. It is useful to filter
// the different flyovers that can be passed to WithScionPath.
func WithNow(now time.Time) ReservationModFcn {
	return func(r *Reservation) error {
		r.Now = now
		return nil
	}
}

// WithMinBW modifies the minimum bandwidth required when filtering flyovers at the time of
// reservation creation.
func WithMinBW(bw uint16) ReservationModFcn {
	return func(r *Reservation) error {
		r.MinBW = bw
		return nil
	}
}

// WithDstIA changes the destination IA of the reservation.
func WithDstIA(dstIA addr.IA) ReservationModFcn {
	return func(r *Reservation) error {
		r.DstIA = dstIA
		return nil
	}
}

// WithScionPath allows to build a Reservation based on the SCION path and flyovers passed as
// arguments. If no flyover is found for a hop, that hop will not have priority.
// The flyover map is modified by removing those flyovers that were used during the reservation.
func WithScionPath(p snet.Path, flyoverMap FlyoverMap) ReservationModFcn {
	return func(r *Reservation) error {
		switch p := p.Dataplane().(type) {
		case SCION:
			scion := &scion.Decoded{}
			if err := scion.DecodeFromBytes(p.Raw); err != nil {
				return serrors.Join(err, serrors.New("failed to Prepare Hummingbird Path"))
			}
			r.Dec = &hummingbird.Decoded{}
			r.Dec.ConvertFromScionDecoded(scion)
		default:
			return serrors.New("Unsupported path type")
		}
		// Extend the number of hops to that of the path.
		r.Hops = make([]*FlyoverData, len(r.Dec.HopFields))

		// We use the path metadata to get the IAs and interface ID sequence from it.
		r.metadata = p.Metadata()
		interfaces := p.Metadata().Interfaces
		baseHops := InterfacesToBaseHops(interfaces)

		// Set the destination IA from the path metadata:
		r.DstIA = baseHops[len(baseHops)-1].IA

		hfIndices := reservationHopFieldIndicesForFlyovers(r.Dec)
		if len(hfIndices) != len(baseHops) {
			return serrors.New("inconsistent path metadata to hop-field mapping",
				"base_hops", len(baseHops), "hop_fields", len(hfIndices))
		}
		for i, baseHop := range baseHops {
			r.SetFlyover(hfIndices[i], consumeFlyover(flyoverMap, baseHop))
		}

		return nil
	}
}

func (r *Reservation) SetFlyover(
	hfIdx uint8,
	flyover *FlyoverData,
) {
	r.Hops[hfIdx] = flyover
	if !flyover.IsFlyover {
		return
	}

	// Find the hop field from its index.
	hf := &r.Dec.HopFields[hfIdx]

	if !hf.Flyover {
		// Because we are setting a plain hop field as a flyover, it will use two more lines.
		r.Dec.NumLines += 2
		r.Dec.PathMeta.SegLen[r.Dec.InfIndexForHFIndex(hfIdx)] += 2
		hf.Flyover = true
	}

	hf.Bw = flyover.Bw
	hf.Duration = flyover.Duration
	hf.ResID = flyover.ResID
}

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

func consumeFlyover(flyoverMap FlyoverMap, baseHop BaseHop) *FlyoverData {
	if flyover, ok := flyoverMap[baseHop]; ok {
		flyover.IsFlyover = true
		delete(flyoverMap, baseHop)
		return flyover
	}
	return &FlyoverData{
		BaseHop:   baseHop,
		IsFlyover: false,
	}
}

// reservationHopFieldIndicesForFlyovers returns the hop field indices in the Hummingbird path
// where flyovers would be written.
// I.e., Hummingbird requires its crossover hop between segments seg1->seg2
// to contain the flyover at the first hop, which is the last hop of seg1. Not all hop fields can
// contain flyovers.
func reservationHopFieldIndicesForFlyovers(dec *hummingbird.Decoded) []uint8 {
	indices := make([]uint8, 0, len(dec.HopFields))
	if dec.NumINF == 0 {
		return indices
	}

	segmentStart := 0

	// Segment 0: include all hops.
	hopCount := int(dec.Base.PathMeta.SegLen[0]) / hummingbird.HopLines
	for hopInSegment := 0; hopInSegment < hopCount; hopInSegment++ {
		indices = append(indices, uint8(segmentStart+hopInSegment))
	}
	segmentStart += hopCount

	// Remaining segments: skip the first hop in each segment.
	for segIdx := 1; segIdx < dec.NumINF; segIdx++ {
		hopCount = int(dec.Base.PathMeta.SegLen[segIdx]) / hummingbird.HopLines
		for hopInSegment := 1; hopInSegment < hopCount; hopInSegment++ {
			indices = append(indices, uint8(segmentStart+hopInSegment))
		}
		segmentStart += hopCount
	}
	return indices
}

// BaseHop describes a pair of Ingress and Egress interfaces in a specific AS
type BaseHop struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}

type FlyoverData struct {
	BaseHop

	IsFlyover bool     // If false, the rest of the fields in this struct are moot.
	ResID     uint32   // Unique per AS.
	Ak        [16]byte // Authentication key.
	Bw        uint16
	StartTime uint32 // Unix timestamp for the start of the reservation.
	Duration  uint16 // Duration of the reservation in seconds.
}

// FlyoverMap is a map between a flyover <IA,ingress,egress> and its corresponding data.
type FlyoverMap map[BaseHop]*FlyoverData

func FlyoversToMap(flyovers []*FlyoverData) FlyoverMap {
	ret := make(FlyoverMap)
	for _, flyover := range flyovers {
		k := BaseHop{
			IA:      flyover.IA,
			Ingress: flyover.Ingress,
			Egress:  flyover.Egress,
		}
		ret[k] = flyover
	}
	return ret
}

// InterfacesToBaseHops maps path metadata interfaces to per-AS ingress/egress hop tuples.
func InterfacesToBaseHops(ifaces []snet.PathInterface) []BaseHop {
	if len(ifaces) == 0 {
		return nil
	}
	baseHops := make([]BaseHop, 0, len(ifaces)/2+1)
	baseHops = append(baseHops, BaseHop{
		IA:      ifaces[0].IA,
		Ingress: 0,
		Egress:  uint16(ifaces[0].ID),
	})

	for i := 1; i < len(ifaces); i += 2 {
		egress := uint16(0)
		if i+1 < len(ifaces) {
			egress = uint16(ifaces[i+1].ID)
		}
		baseHops = append(baseHops, BaseHop{
			IA:      ifaces[i].IA,
			Ingress: uint16(ifaces[i].ID),
			Egress:  egress,
		})
	}
	return baseHops
}

// GetFlyoversForPath returns a FlyoverMap with all returned flyovers for the given path.
// Compatibility wrapper: keeps the old mocked behavior.
// TODO remove this temporary function and modify tests.
func GetFlyoversForPath(p snet.Path, startTime uint32) (FlyoverMap, error) {
	interfaces := p.Metadata().Interfaces
	if len(interfaces) == 0 {
		return FlyoverMap{}, nil
	}
	baseHops := InterfacesToBaseHops(interfaces)
	return getFlyoversForHops(baseHops, startTime)
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

func getFlyoversForHops(baseHops []BaseHop, startTime uint32) (FlyoverMap, error) {
	// For each found triplet <AS,ingress,egress> call redeemFlyover and store the result.
	redeemed := make([]*FlyoverData, len(baseHops))
	var wg sync.WaitGroup
	wg.Add(len(baseHops))
	for i := range baseHops {
		go func(i int) {
			defer wg.Done()
			redeemed[i] = redeemFlyover(baseHops[i], startTime)
		}(i)
	}
	wg.Wait()

	flyovers := make(FlyoverMap, len(baseHops))
	for i, baseHop := range baseHops {
		flyovers[baseHop] = redeemed[i]
	}

	return flyovers, nil
}

// redeemFlyover mocks the redemption of a flyover for a given AS, ingress, and egress interfaces.
// The real function will require a daemon.Connector to find a path to the given AS, or the path
// to the given AS.
func redeemFlyover(baseHop BaseHop, startTime uint32) *FlyoverData {
	return &FlyoverData{
		BaseHop:   baseHop,
		IsFlyover: true,
		ResID:     1,
		StartTime: startTime,
		Duration:  10,
		Bw:        64,
		Ak:        [16]byte{},
	}
}
