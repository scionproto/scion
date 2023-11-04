// Copyright 2023 Anapaya Systems
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

	"github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/pkg/proto/gateway"
)

// IPPrefixServer serves IP prefix requests.
type IPPrefixServer struct {
	*grpc.IPPrefixServer
}

func (s IPPrefixServer) Prefixes(
	ctx context.Context,
	req *connect.Request[gateway.PrefixesRequest],
) (*connect.Response[gateway.PrefixesResponse], error) {

	rep, err := s.IPPrefixServer.Prefixes(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
