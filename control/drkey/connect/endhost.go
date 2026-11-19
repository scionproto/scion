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

package connect

import (
	"context"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/endhost"
)

type EndhostDRKeyServer struct {
	*grpc.Server
}

func (e EndhostDRKeyServer) DRKeyASHost(ctx context.Context,
	req *connect.Request[endhost.DRKeyASHostRequest]) (
	*connect.Response[endhost.DRKeyASHostResponse], error) {

	rep, err := e.Server.DRKeyASHost(ctx, &control_plane.DRKeyASHostRequest{
		ValTime:    req.Msg.ValTime,
		ProtocolId: req.Msg.ProtocolId,
		SrcIa:      req.Msg.SrcIa,
		DstIa:      req.Msg.DstIa,
		DstHost:    req.Msg.DstHost,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&endhost.DRKeyASHostResponse{
		EpochBegin: rep.EpochBegin,
		EpochEnd:   rep.EpochEnd,
		Key:        rep.Key,
	}), nil
}

func (e EndhostDRKeyServer) DRKeyHostAS(ctx context.Context,
	req *connect.Request[endhost.DRKeyHostASRequest]) (
	*connect.Response[endhost.DRKeyHostASResponse], error) {

	rep, err := e.Server.DRKeyHostAS(ctx, &control_plane.DRKeyHostASRequest{
		ValTime:    req.Msg.ValTime,
		ProtocolId: req.Msg.ProtocolId,
		SrcIa:      req.Msg.SrcIa,
		DstIa:      req.Msg.DstIa,
		SrcHost:    req.Msg.SrcHost,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&endhost.DRKeyHostASResponse{
		EpochBegin: rep.EpochBegin,
		EpochEnd:   rep.EpochEnd,
		Key:        rep.Key,
	}), nil
}

func (e EndhostDRKeyServer) DRKeyHostHost(ctx context.Context,
	req *connect.Request[endhost.DRKeyHostHostRequest]) (
	*connect.Response[endhost.DRKeyHostHostResponse], error) {

	rep, err := e.Server.DRKeyHostHost(ctx, &control_plane.DRKeyHostHostRequest{
		ValTime:    req.Msg.ValTime,
		ProtocolId: req.Msg.ProtocolId,
		SrcIa:      req.Msg.SrcIa,
		DstIa:      req.Msg.DstIa,
		DstHost:    req.Msg.DstHost,
		SrcHost:    req.Msg.SrcHost,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&endhost.DRKeyHostHostResponse{
		EpochBegin: rep.EpochBegin,
		EpochEnd:   rep.EpochEnd,
		Key:        rep.Key,
	}), nil
}
