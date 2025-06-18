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
	"github.com/scionproto/scion/control/trust/grpc"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
)

var _ control_planeconnect.TrustMaterialServiceHandler = MaterialServer{}

type MaterialServer struct {
	*grpc.MaterialServer
}

func (m MaterialServer) Chains(ctx context.Context, req *connect.Request[control_plane.ChainsRequest]) (*connect.Response[control_plane.ChainsResponse], error) {
	rep, err := m.MaterialServer.Chains(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (m MaterialServer) TRC(ctx context.Context, req *connect.Request[control_plane.TRCRequest]) (*connect.Response[control_plane.TRCResponse], error) {
	rep, err := m.MaterialServer.TRC(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
