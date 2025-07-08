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

	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/private/ca/renewal/grpc"
)

var _ control_planeconnect.ChainRenewalServiceHandler = RenewalServer{}

type RenewalServer struct {
	*grpc.RenewalServer
}

func (m RenewalServer) ChainRenewal(
	ctx context.Context,
	req *connect.Request[control_plane.ChainRenewalRequest],
) (*connect.Response[control_plane.ChainRenewalResponse], error) {
	rep, err := m.RenewalServer.ChainRenewal(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
