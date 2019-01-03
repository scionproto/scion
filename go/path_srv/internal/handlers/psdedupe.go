// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/snet"
)

type segReq struct {
	segReq *path_mgmt.SegReq
	server net.Addr
	id     uint64
}

func (req *segReq) DedupeKey() string {
	if sAddr, ok := req.server.(*snet.Addr); ok {
		return fmt.Sprintf("%s %s", req.segReq, sAddr.Desc())
	}
	return fmt.Sprintf("%s %s", req.segReq, req.server)
}

func (req *segReq) BroadcastKey() string {
	return fmt.Sprintf("%s %s", req.segReq, req.server)
}

func NewGetSegsDeduper(msger infra.Messenger) dedupe.Deduper {
	requestFunc := func(ctx context.Context, request dedupe.Request) dedupe.Response {
		req := request.(*segReq)
		segs, err := msger.GetSegs(ctx, req.segReq, req.server, req.id)
		if err != nil {
			return dedupe.Response{Error: err}
		}
		return dedupe.Response{Data: segs}
	}
	return dedupe.New(requestFunc, time.Second, 0)
}
