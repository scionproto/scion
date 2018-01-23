// Copyright 2018 ETH Zurich
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

package infra

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// Interface Handler is implemented by objects that can handle a request coming
// from a remote SCION network node.
type Handler interface {
	Handle(ctx context.Context)
}

// Constructs a handler for message msg. Handle() can be called on the
// resulting object to process the message.
type HandlerConstructor func(msg, fullMsg proto.Cerealizable, peer net.Addr) (Handler, error)

var (
	// MessengerContextKey is a context key. It can be used in SCION infra
	// request handlers to access the messaging layer the message arrived on.
	MessengerContextKey = &contextKey{"infra-messenger"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "infra/messenger context value " + k.name
}

type Messenger interface {
	RecvMsg(ctx context.Context) (proto.Cerealizable, net.Addr, error)
	GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr) (*cert_mgmt.TRC, error)
	SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr) error
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr) (*cert_mgmt.Chain, error)
	SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr) error
	AddHandler(msgType string, f HandlerConstructor)
	ListenAndServe()
	CloseServer() error
}
