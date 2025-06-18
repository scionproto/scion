// Copyright 2025 SCION Association, Anapaya Systems
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
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
)

var (
	_ control_planeconnect.DRKeyInterServiceHandler = Server{}
	_ control_planeconnect.DRKeyIntraServiceHandler = Server{}
)

type Server struct {
	*grpc.Server
}

func (m Server) DRKeyLevel1(ctx context.Context, req *connect.Request[control_plane.DRKeyLevel1Request]) (*connect.Response[control_plane.DRKeyLevel1Response], error) {
	rep, err := m.Server.DRKeyLevel1(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m Server) DRKeyIntraLevel1(ctx context.Context, req *connect.Request[control_plane.DRKeyIntraLevel1Request]) (*connect.Response[control_plane.DRKeyIntraLevel1Response], error) {
	rep, err := m.Server.DRKeyIntraLevel1(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m Server) DRKeyASHost(ctx context.Context, req *connect.Request[control_plane.DRKeyASHostRequest]) (*connect.Response[control_plane.DRKeyASHostResponse], error) {
	rep, err := m.Server.DRKeyASHost(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m Server) DRKeyHostAS(ctx context.Context, req *connect.Request[control_plane.DRKeyHostASRequest]) (*connect.Response[control_plane.DRKeyHostASResponse], error) {
	rep, err := m.Server.DRKeyHostAS(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m Server) DRKeyHostHost(ctx context.Context, req *connect.Request[control_plane.DRKeyHostHostRequest]) (*connect.Response[control_plane.DRKeyHostHostResponse], error) {
	rep, err := m.Server.DRKeyHostHost(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m Server) DRKeySecretValue(ctx context.Context, req *connect.Request[control_plane.DRKeySecretValueRequest]) (*connect.Response[control_plane.DRKeySecretValueResponse], error) {
	rep, err := m.Server.DRKeySecretValue(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
