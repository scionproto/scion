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

package messenger

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/proto"
)

var _ infra.Messenger = (*MockMessenger)(nil)

type MockMessenger struct {
	TRCs   map[addr.ISD]*trc.TRC
	Chains map[addr.IA]*cert.Chain
}

func (m *MockMessenger) RecvMsg(ctx context.Context) (proto.Cerealizable, net.Addr, error) {
	panic("not implemented")
}

func (m *MockMessenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

	trcObj, ok := m.TRCs[msg.ISD]
	if !ok {
		return nil, common.NewBasicError("TRC not found", nil)
	}

	compressedTRC, err := trcObj.Compress()
	if err != nil {
		return nil, common.NewBasicError("Unable to compress TRC", nil)
	}
	return &cert_mgmt.TRC{RawTRC: compressedTRC}, nil
}

func (m *MockMessenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr,
	id uint64) error {

	panic("not implemented")
}

func (m *MockMessenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	chain, ok := m.Chains[msg.IA()]
	if !ok {
		return nil, common.NewBasicError("Chain not found", nil)
	}

	compressedChain, err := chain.Compress()
	if err != nil {
		return nil, common.NewBasicError("Unable to compress Chain", nil)
	}
	return &cert_mgmt.Chain{RawChain: compressedChain}, nil
}

func (m *MockMessenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	panic("not implemented")
}

func (m *MockMessenger) AddHandler(msgType string, h infra.Handler) {
	panic("not implemented")
}

func (m *MockMessenger) ListenAndServe() {
	panic("not implemented")
}

func (m *MockMessenger) CloseServer() error {
	panic("not implemented")
}

type MockAddress struct{}

func (f *MockAddress) Network() string {
	return "mock network"
}

func (f *MockAddress) String() string {
	return "mock address"
}
