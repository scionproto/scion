// Copyright 2019 ETH Zurich
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

package messenger

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
)

var _ infra.ResponseWriter = (*UDPResponseWriter)(nil)

type UDPResponseWriter struct {
	Messenger infra.Messenger
	Remote    net.Addr
	ID        uint64
}

func (rw *UDPResponseWriter) SendAckReply(ctx context.Context, msg *ack.Ack) error {
	return rw.Messenger.SendAck(ctx, msg, rw.Remote, rw.ID)
}

func (rw *UDPResponseWriter) SendTRCReply(ctx context.Context, msg *cert_mgmt.TRC) error {
	return rw.Messenger.SendTRC(ctx, msg, rw.Remote, rw.ID)
}

func (rw *UDPResponseWriter) SendCertChainReply(ctx context.Context, msg *cert_mgmt.Chain) error {
	return rw.Messenger.SendCertChain(ctx, msg, rw.Remote, rw.ID)
}

func (rw *UDPResponseWriter) SendChainIssueReply(ctx context.Context,
	msg *cert_mgmt.ChainIssRep) error {

	return rw.Messenger.SendChainIssueReply(ctx, msg, rw.Remote, rw.ID)
}

func (rw *UDPResponseWriter) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply) error {
	return rw.Messenger.SendSegReply(ctx, msg, rw.Remote, rw.ID)
}
