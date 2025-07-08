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

	"github.com/scionproto/scion/pkg/experimental/hiddenpath/grpc"
	"github.com/scionproto/scion/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/pkg/proto/hidden_segment/v1/hidden_segmentconnect"
)

var (
	_ hidden_segmentconnect.HiddenSegmentLookupServiceHandler = SegmentServer{}
)

type SegmentServer struct {
	*grpc.SegmentServer
}

func (m SegmentServer) HiddenSegments(
	ctx context.Context,
	req *connect.Request[hidden_segment.HiddenSegmentsRequest],
) (*connect.Response[hidden_segment.HiddenSegmentsResponse], error) {
	rep, err := m.SegmentServer.HiddenSegments(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}
