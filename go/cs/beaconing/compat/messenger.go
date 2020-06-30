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

package compat

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
)

// RPC is an adapter for infra.Messenger
type RPC struct {
	Messenger infra.Messenger
}

// RegisterSegment registers a segment with the remote.
func (rpc RPC) RegisterSegment(ctx context.Context, meta seg.Meta, remote net.Addr) error {
	req := &path_mgmt.SegReg{
		SegRecs: &path_mgmt.SegRecs{
			Recs: []*seg.Meta{&meta},
		},
	}
	return rpc.Messenger.SendSegReg(ctx, req, remote, messenger.NextId())
}
