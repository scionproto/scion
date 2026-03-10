package path

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/pkg/slayers/path"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/require"
)

type fakeReservationRequester struct {
	redeem func(context.Context, net.Addr, *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error)
}

func (f fakeReservationRequester) Redeem(
	ctx context.Context,
	dst net.Addr,
	req *hbirdv1.RedemptionRequests,
) (*hbirdv1.RedemptionResponses, error) {
	return f.redeem(ctx, dst, req)
}

func TestReservationRedeemFlyovers_InjectableRequesterAndLookup(t *testing.T) {
	ia1 := addr.MustParseIA("1-ff00:0:111")
	ia2 := addr.MustParseIA("1-ff00:0:112")
	r := reservationForRedemptionTests(ia1, ia2)

	r.redemption.lookup = func(context.Context, addr.IA) (snet.Path, error) {
		return redemptionPathForIA(t, ia1, ia2), nil
	}
	r.redemption.requester = fakeReservationRequester{redeem: func(_ context.Context, dst net.Addr,
		_ *hbirdv1.RedemptionRequests,
	) (*hbirdv1.RedemptionResponses, error) {
		udp := dst.(*snet.UDPAddr)
		return &hbirdv1.RedemptionResponses{Reservation: []*hbirdv1.Reservation{{
			Ia:      uint64(udp.IA),
			ResId:   7,
			AuthKey: []byte("1234567890abcdefEXTRA"),
		}}}, nil
	}}

	err := r.RedeemFlyovers(context.Background())
	require.NoError(t, err)
	require.True(t, r.Hops[0].IsFlyover)
	require.Equal(t, uint32(7), r.Hops[0].ResID)
	require.True(t, r.Hops[1].IsFlyover)
	require.Equal(t, uint32(7), r.Hops[1].ResID)
}

func TestReservationRedeemFlyovers_DefaultConfig_UsesStoredRuntime(t *testing.T) {
	ia1 := addr.MustParseIA("1-ff00:0:111")
	ia2 := addr.MustParseIA("1-ff00:0:112")
	r := reservationForRedemptionTests(ia1, ia2)

	var gotReq *hbirdv1.RedemptionRequests
	r.redemption.lookup = func(context.Context, addr.IA) (snet.Path, error) {
		return redemptionPathForIA(t, ia1, ia2), nil
	}
	r.redemption.requester = fakeReservationRequester{redeem: func(_ context.Context, _ net.Addr,
		req *hbirdv1.RedemptionRequests,
	) (*hbirdv1.RedemptionResponses, error) {
		gotReq = req
		return &hbirdv1.RedemptionResponses{Reservation: []*hbirdv1.Reservation{{
			Ia:      uint64(ia1),
			ResId:   9,
			AuthKey: []byte("1234567890abcdefEXTRA"),
		}}}, nil
	}}

	mod := WithRedemptionOptions(
		WithFlyoverStartTime(111),
		WithFlyoverBandwidth(77),
		WithFlyoverDuration(10),
		WithFlyoverClientKey([]byte("dummy")),
	)
	require.NoError(t, mod(r))

	err := r.RedeemFlyovers(context.Background())
	require.NoError(t, err)
	require.NotNil(t, gotReq)
	require.Equal(t, uint32(77), gotReq.Redemption[0].RedInfo.Bw)
	require.Equal(t, uint32(111), gotReq.Redemption[0].RedInfo.StartTime)
	require.Equal(t, uint32(10), gotReq.Redemption[0].RedInfo.Duration)
	require.Equal(t, []byte("dummy"), gotReq.ClientKey)
}

func TestReservationRedeemFlyovers_DefaultRequester_BestEffort(t *testing.T) {
	ia1 := addr.MustParseIA("1-ff00:0:111")
	ia2 := addr.MustParseIA("1-ff00:0:112")
	r := reservationForRedemptionTests(ia1, ia2)

	called := false
	r.redemption.requester = nil
	r.redemption.dialer = nil
	r.redemption.dialerFactory = func(context.Context, string) (libconnect.Dialer, error) {
		called = true
		return nil, errors.New("boom")
	}

	err := r.RedeemFlyovers(context.Background())
	require.Error(t, err)
	require.True(t, called)
	require.Contains(t, err.Error(), "building default redemption dialer")
}

func TestReservationRedeemFlyovers_DefaultPathLookup_UsesConfiguredDaemon(t *testing.T) {
	ia1 := addr.MustParseIA("1-ff00:0:111")
	ia2 := addr.MustParseIA("1-ff00:0:112")
	r := reservationForRedemptionTests(ia1, ia2)

	r.redemption.lookup = nil
	r.redemption.daemonAddr = "127.0.0.1:1"
	r.redemption.requester = fakeReservationRequester{redeem: func(context.Context, net.Addr,
		*hbirdv1.RedemptionRequests,
	) (*hbirdv1.RedemptionResponses, error) {
		return &hbirdv1.RedemptionResponses{}, nil
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := r.RedeemFlyovers(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path lookup failed")
	require.Contains(t, err.Error(), "127.0.0.1:1")
}

func reservationForRedemptionTests(ia1, ia2 addr.IA) *Reservation {
	r := &Reservation{
		DstIA: ia2,
		Now:   func() time.Time { return time.Unix(100, 0) },
		Dec: &dphum.Decoded{
			Base: dphum.Base{
				PathMeta: dphum.MetaHdr{SegLen: [3]uint8{6, 0, 0}},
				NumINF:   1,
				NumLines: 6,
			},
			HopFields: []dphum.FlyoverHopField{{
				HopField: path.HopField{ConsIngress: 1, ConsEgress: 0, ExpTime: 8},
			}, {
				HopField: path.HopField{ConsIngress: 2, ConsEgress: 0, ExpTime: 8},
			}},
		},
		Hops: []*FlyoverData{{}, {}},
		metadata: &snet.PathMetadata{
			Interfaces: []snet.PathInterface{{IA: ia1, ID: 1}, {IA: ia2, ID: 2}},
			Notes: []string{
				`{"hummingbird-v0":{"supported":true}}`,
				`{"hummingbird-v0":{"supported":true}}`,
			},
		},
		redemption: newFlyoverRedemptionConfig(0, 0, nil),
	}
	return r
}

func redemptionPathForIA(t *testing.T, ia1, ia2 addr.IA) Path {
	t.Helper()
	return Path{
		Src:           ia1,
		Dst:           ia2,
		DataplanePath: Empty{},
		NextHop:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 30000},
		Meta: snet.PathMetadata{DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
			ia1: {ControlServices: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.20:30252")}},
			ia2: {ControlServices: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.21:30252")}},
		}},
	}
}
