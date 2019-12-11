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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// RPC abstracts the RPC calls over the messenger.
type RPC interface {
	GetTRC(context.Context, TRCReq, net.Addr) ([]byte, error)
	GetCertChain(ctx context.Context, msg ChainReq, a net.Addr) ([]byte, error)
	SendTRC(context.Context, []byte, net.Addr) error
	SendCertChain(context.Context, []byte, net.Addr) error
	SetMsgr(msgr infra.Messenger)
}

// TRCReq holds the values of a TRC request.
type TRCReq struct {
	ISD     addr.ISD
	Version scrypto.Version
}

func (r TRCReq) withVersion(version scrypto.Version) TRCReq {
	r.Version = version
	return r
}

// ChainReq holds the values of a certificate chain request.
type ChainReq struct {
	IA      addr.IA
	Version scrypto.Version
}
