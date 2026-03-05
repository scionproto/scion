package grpc

import (
	"context"
	"math"

	hb "github.com/scionproto/scion/hbird"
	hbirdconnect "github.com/scionproto/scion/hbird/hbserver/connect"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/private/topology"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// Wire format constants
	BW_BITS          = 10
	BW_EXP_BITS      = 5
	RESID_BITS       = 22
	MAX_DURATION_SEC = math.MaxUint16
)

type HBirdServer struct {
	Topo      *topology.Loader
	HbService *hbirdconnect.HummingbirdKeyDerivationService
	Icm       *hb.IntervalColorMap
	hbirdv1.UnimplementedHBirdServiceServer
}

func (H HBirdServer) Redeem(ctx context.Context, requests *hbirdv1.RedemptionRequests) (*hbirdv1.RedemptionResponses, error) {
	//TODO implement me
	panic("implement me")
}

func (H HBirdServer) Status(ctx context.Context, empty *emptypb.Empty) (*hbirdv1.StatusResponse, error) {
	res := &hbirdv1.StatusResponse{Version: 0}
	return res, nil
}
