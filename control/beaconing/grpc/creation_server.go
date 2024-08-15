// Copyright 2020 Anapaya Systems
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

package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

// BeaconHandler handles the received beacons.
type BeaconHandler interface {
	HandleBeacon(ctx context.Context, b beacon.Beacon, peer *snet.UDPAddr) error
}

// SegmentCreationServer handles beaconing requests.
type SegmentCreationServer struct {
	Handler BeaconHandler
}

func (s SegmentCreationServer) Beacon(ctx context.Context,
	req *cppb.BeaconRequest) (*cppb.BeaconResponse, error) {

	gPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, serrors.New("peer must exist")
	}
	logger := log.FromCtx(ctx)

	peer, ok := gPeer.Addr.(*snet.UDPAddr)
	if !ok {
		logger.Debug("peer must be *snet.UDPAddr", "actual", fmt.Sprintf("%T", gPeer))
		return nil, serrors.New("peer must be *snet.UDPAddr", "actual", fmt.Sprintf("%T", gPeer))
	}
	ingress, err := extractIngressIfID(peer.Path)
	if err != nil {
		logger.Debug("Failed to extract ingress interface", "peer", peer, "err", err)
		return nil, status.Error(codes.InvalidArgument, "failed to extract ingress interface")
	}
	ps, err := seg.BeaconFromPB(req.Segment)
	if err != nil {
		logger.Debug("Failed to parse beacon", "peer", peer, "err", err)
		return nil, status.Error(codes.InvalidArgument, "failed to parse beacon")
	}
	b := beacon.Beacon{
		Segment: ps,
		InIfID:  ingress,
	}
	if err := s.Handler.HandleBeacon(ctx, b, peer); err != nil {
		logger.Debug("Failed to handle beacon", "peer", peer, "err", err)
		// TODO(roosd): return better error with status code.
		return nil, serrors.Wrap("handling beacon", err)
	}
	return &cppb.BeaconResponse{}, nil

}

// extractIngressIfID extracts the ingress interface ID from a path.
func extractIngressIfID(path snet.DataplanePath) (uint16, error) {
	invertedPath, ok := path.(snet.RawReplyPath)
	if !ok {
		return 0, serrors.New("unexpected path", "type", common.TypeOf(path))
	}
	rawScionPath, ok := invertedPath.Path.(*scion.Raw)
	if !ok {
		return 0, serrors.New("unexpected path", "type", common.TypeOf(path))
	}
	hf, err := rawScionPath.GetCurrentHopField()
	if err != nil {
		return 0, serrors.Wrap("getting current hop field", err)
	}
	return hf.ConsIngress, nil
}
