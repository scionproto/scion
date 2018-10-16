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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
)

type segReq struct {
	segReq *path_mgmt.SegReq
	server net.Addr
	id     uint64
}

func (req *segReq) DedupeKey() string {
	return fmt.Sprintf("%s %s", req.segReq, req.server)
}

func (req *segReq) BroadcastKey() string {
	return fmt.Sprintf("%s %s", req.segReq, req.server)
}

type psDeduper struct {
	msger infra.Messenger
}

func (pd *psDeduper) segsRequestFunc(ctx context.Context,
	request dedupe.Request) dedupe.Response {

	req := request.(*segReq)
	segs, err := pd.msger.GetSegs(ctx, req.segReq, req.server, req.id)
	if err != nil {
		return dedupe.Response{Error: err}
	}
	return dedupe.Response{Data: segs}
}

func NewDeduper(msger infra.Messenger) *dedupe.Deduper {
	psd := &psDeduper{msger: msger}
	return dedupe.New(psd.segsRequestFunc, 0, 0)
}

func (h *segReqHandler) getSegsFromNetwork(ctx context.Context,
	req *path_mgmt.SegReq, server net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	responseC, cancelF := h.segsDeduper.Request(ctx, &segReq{
		segReq: req,
		server: server,
		id:     id,
	})
	defer cancelF()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Data.(*path_mgmt.SegReply), nil
	case <-ctx.Done():
		return nil, common.NewBasicError("Context done while waiting for Segs",
			ctx.Err())
	}
}
