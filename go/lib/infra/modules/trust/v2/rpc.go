// Copyright 2019 Anapaya Systems
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

package trust

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
)

// RPC abstracts the RPC calls over the messenger.
type RPC interface {
	GetTRC(context.Context, *cert_mgmt.TRCReq, net.Addr) (*cert_mgmt.TRC, error)
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr) (*cert_mgmt.Chain, error)
	SendTRC(context.Context, *cert_mgmt.TRC, net.Addr) error
	SendCertChain(context.Context, *cert_mgmt.Chain, net.Addr) error
	SetMsgr(msgr infra.Messenger)
}
