package connect

import (
	"context"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/bufgen/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/onehop"
	"github.com/scionproto/scion/pkg/addr"
	control_plane "github.com/scionproto/scion/pkg/proto/control_plane"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet/squic"
)

type BeaconSenderFactory struct {
	Dialer func(net.Addr) squic.EarlyDialer
}

func (f *BeaconSenderFactory) NewSender(
	ctx context.Context,
	dstIA addr.IA,
	egIfId uint16,
	nextHop *net.UDPAddr,
) (beaconing.Sender, error) {
	addr := &onehop.Addr{
		IA:      dstIA,
		Egress:  egIfId,
		SVC:     addr.SvcCS,
		NextHop: nextHop,
	}
	dialer := f.Dialer(addr)
	return &BeaconSender{
		Addr: "https://" + addr.SVC.BaseString(),
		Client: &HTTPClient{
			RoundTripper: &http3.RoundTripper{
				Dial: dialer.DialEarly,
			},
		},
	}, nil

}

type BeaconSender struct {
	Addr   string
	Client *HTTPClient
}

func (s BeaconSender) Send(ctx context.Context, b *seg.PathSegment) error {
	client := control_planeconnect.NewSegmentCreationServiceClient(s.Client, s.Addr)
	_, err := client.Beacon(ctx, connect.NewRequest(&control_plane.BeaconRequest{
		Segment: seg.PathSegmentToPB(b),
	}))
	return err
}

// Close closes the BeaconSender and releases all underlying resources.
func (s BeaconSender) Close() error {
	return s.Client.RoundTripper.Close()
}

type HTTPClient struct {
	RoundTripper *http3.RoundTripper
}

func (c HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.RoundTripper.RoundTrip(req)
}
