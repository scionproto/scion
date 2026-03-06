package path_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/types"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/require"
)

type fakeRedemptionRequester struct {
	responses map[addr.IA]*hbirdv1.RedemptionResponses
	errors    map[addr.IA]error
}

func (f fakeRedemptionRequester) Redeem(
	_ context.Context,
	dst net.Addr,
	_ *hbirdv1.RedemptionRequests,
) (*hbirdv1.RedemptionResponses, error) {
	udp, ok := dst.(*snet.UDPAddr)
	if !ok {
		return nil, errors.New("unexpected address type")
	}
	if err, ok := f.errors[udp.IA]; ok {
		return nil, err
	}
	if resp, ok := f.responses[udp.IA]; ok {
		return resp, nil
	}
	return nil, errors.New("missing fake response")
}

type fakePathResolver struct {
	lookup func(context.Context, addr.IA, addr.IA, types.PathReqFlags) ([]snet.Path, error)
}

func (f fakePathResolver) Paths(ctx context.Context, dst, src addr.IA, flags types.PathReqFlags) ([]snet.Path, error) {
	return f.lookup(ctx, dst, src, flags)
}

func TestGetFlyoversForPathWithRedemption_PartialSuccess(t *testing.T) {
	ia0 := addr.MustParseIA("1-ff00:0:110")
	ia1 := addr.MustParseIA("1-ff00:0:111")
	ia2 := addr.MustParseIA("1-ff00:0:112")

	basePath := path.Path{
		Src:           ia0,
		Dst:           ia2,
		DataplanePath: path.Empty{},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ia0, ID: 1},
				{IA: ia1, ID: 1},
				{IA: ia1, ID: 2},
				{IA: ia2, ID: 2},
			},
			Notes: []string{
				`{"hummingbird-v0":{"supported":false}}`,
				`{"hummingbird-v0":{"supported":true}}`,
				`{"hummingbird-v0":{"supported":true}}`,
			},
		},
	}

	resolver := fakePathResolver{
		lookup: func(_ context.Context, dst, _ addr.IA, _ types.PathReqFlags) ([]snet.Path, error) {
			return []snet.Path{path.Path{
				Src:           addr.MustParseIA("1-ff00:0:110"),
				Dst:           dst,
				DataplanePath: path.Empty{},
				NextHop:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 30000},
				Meta: snet.PathMetadata{DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
					dst: {
						ControlServices: []netip.AddrPort{
							netip.AddrPortFrom(netip.MustParseAddr("127.0.0.20"), 30252),
						},
					},
				}},
			}}, nil
		}}

	requester := fakeRedemptionRequester{
		responses: map[addr.IA]*hbirdv1.RedemptionResponses{
			ia1: {
				Reservation: []*hbirdv1.Reservation{{
					Ia:      uint64(ia1),
					ResId:   42,
					AuthKey: []byte("1234567890abcdefEXTRA"),
				}},
			},
		},
		errors: map[addr.IA]error{ia2: errors.New("simulated redeem failure")},
	}

	got, err := path.GetFlyoversForPathWithRedemption(
		context.Background(),
		resolver,
		basePath,
		path.WithFlyoverRedemptionRequester(requester),
		path.WithFlyoverClientKey([]byte("dummy")),
		path.WithFlyoverStartTime(111),
		path.WithFlyoverBandwidth(77),
		path.WithFlyoverDuration(10),
	)
	require.Error(t, err)
	require.Len(t, got, 3)

	hop0 := path.BaseHop{IA: ia0, Ingress: 0, Egress: 1}
	hop1 := path.BaseHop{IA: ia1, Ingress: 1, Egress: 2}
	hop2 := path.BaseHop{IA: ia2, Ingress: 2, Egress: 0}
	require.False(t, got[hop0].IsFlyover)
	require.True(t, got[hop1].IsFlyover)
	require.Equal(t, uint32(42), got[hop1].ResID)
	require.Equal(t, uint16(77), got[hop1].Bw)
	require.False(t, got[hop2].IsFlyover)
}

func TestGetFlyoversForPathWithRedemption_AllFail(t *testing.T) {
	ia0 := addr.MustParseIA("1-ff00:0:110")
	ia := addr.MustParseIA("1-ff00:0:111")
	p := path.Path{
		Src:           ia0,
		Dst:           ia,
		DataplanePath: path.Empty{},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{{IA: ia0, ID: 1}, {IA: ia, ID: 1}},
			Notes:      []string{`{"hummingbird-v0":{"supported":true}}`, `{"hummingbird-v0":{"supported":true}}`},
		},
	}

	resolver := fakePathResolver{lookup: func(_ context.Context, dst, _ addr.IA, _ types.PathReqFlags) ([]snet.Path, error) {
		return []snet.Path{path.Path{
			Src:           addr.MustParseIA("1-ff00:0:110"),
			Dst:           dst,
			DataplanePath: path.Empty{},
			NextHop:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 30000},
			Meta: snet.PathMetadata{DiscoveryInformation: map[addr.IA]snet.DiscoveryInformation{
				dst: {
					ControlServices: []netip.AddrPort{
						netip.AddrPortFrom(netip.MustParseAddr("127.0.0.20"), 30252),
					},
				},
			}},
		}}, nil
	}}

	requester := fakeRedemptionRequester{errors: map[addr.IA]error{ia: errors.New("boom")}}
	got, err := path.GetFlyoversForPathWithRedemption(
		context.Background(),
		resolver,
		p,
		path.WithFlyoverRedemptionRequester(requester),
		path.WithFlyoverClientKey([]byte("dummy")),
	)
	require.Error(t, err)
	require.Len(t, got, 2)
	require.False(t, got[path.BaseHop{IA: ia0, Ingress: 0, Egress: 1}].IsFlyover)
	require.False(t, got[path.BaseHop{IA: ia, Ingress: 1, Egress: 0}].IsFlyover)
}

func TestGetFlyoversForPathWithRedemption_UnsupportedNotes(t *testing.T) {
	ia0 := addr.MustParseIA("1-ff00:0:110")
	ia := addr.MustParseIA("1-ff00:0:111")
	p := path.Path{
		Src:           ia0,
		Dst:           ia,
		DataplanePath: path.Empty{},
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{{IA: ia0, ID: 1}, {IA: ia, ID: 1}},
			Notes:      []string{"not-json", "not-json"},
			Expiry:     time.Now().Add(time.Minute),
		},
	}

	resolver := fakePathResolver{lookup: func(_ context.Context, _, _ addr.IA, _ types.PathReqFlags) ([]snet.Path, error) {
		return nil, errors.New("should not be called")
	}}

	got, err := path.GetFlyoversForPathWithRedemption(
		context.Background(),
		resolver,
		p,
		path.WithFlyoverRedemptionRequester(fakeRedemptionRequester{}),
	)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.False(t, got[path.BaseHop{IA: ia0, Ingress: 0, Egress: 1}].IsFlyover)
	require.False(t, got[path.BaseHop{IA: ia, Ingress: 1, Egress: 0}].IsFlyover)
}
