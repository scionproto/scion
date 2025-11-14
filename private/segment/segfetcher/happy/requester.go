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

package happy

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/connect/happy"
	"github.com/scionproto/scion/private/segment/segfetcher"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	Connect   segfetcher.RPC
	Grpc      segfetcher.RPC
	RpcConfig happy.Config
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) (segfetcher.SegmentsReply, error) {

	return happy.Happy(
		ctx,
		happy.Call2[segfetcher.Request, net.Addr, segfetcher.SegmentsReply]{
			Call:   f.Connect.Segments,
			Input1: req,
			Input2: server,
			Typ:    "control_plane.v1.SegmentLookupService.Segments",
		},
		happy.Call2[segfetcher.Request, net.Addr, segfetcher.SegmentsReply]{
			Call:   f.Grpc.Segments,
			Input1: req,
			Input2: server,
			Typ:    "control_plane.v1.SegmentLookupService.Segments",
		},
		f.RpcConfig,
	)
}
