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
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// RPC abstracts the RPC calls over the messenger.
type RPC interface {
	GetTRC(context.Context, TRCReq, net.Addr) ([]byte, error)
	GetCertChain(context.Context, ChainReq, net.Addr) ([]byte, error)
	SendTRC(context.Context, []byte, net.Addr) error
	SendCertChain(context.Context, []byte, net.Addr) error
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

// Messenger is the part of the infra messenger the trust rpc layer uses.
type Messenger interface {
	GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr,
		id uint64) (*cert_mgmt.TRC, error)
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr,
		id uint64) (*cert_mgmt.Chain, error)
	SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error
	SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr, id uint64) error
}

// DefaultRPC implements the RPC interface using the given messenger.
type DefaultRPC struct {
	Msgr Messenger
}

func (r DefaultRPC) GetTRC(ctx context.Context, req TRCReq, a net.Addr) ([]byte, error) {
	reply, err := r.Msgr.GetTRC(ctx, &cert_mgmt.TRCReq{
		ISD:     req.ISD,
		Version: req.Version,
	}, a, messenger.NextId())
	if err != nil {
		return nil, err
	}
	return reply.RawTRC, nil
}

func (r DefaultRPC) GetCertChain(ctx context.Context, req ChainReq, a net.Addr) ([]byte, error) {
	reply, err := r.Msgr.GetCertChain(ctx, &cert_mgmt.ChainReq{
		RawIA:   req.IA.IAInt(),
		Version: req.Version,
	}, a, messenger.NextId())
	if err != nil {
		return nil, err
	}
	return reply.RawChain, nil
}

func (r DefaultRPC) SendTRC(ctx context.Context, trc []byte, a net.Addr) error {
	return r.Msgr.SendTRC(ctx, &cert_mgmt.TRC{
		RawTRC: trc,
	}, a, messenger.NextId())
}

func (r DefaultRPC) SendCertChain(ctx context.Context, chain []byte, a net.Addr) error {
	return r.Msgr.SendCertChain(ctx, &cert_mgmt.Chain{
		RawChain: chain,
	}, a, messenger.NextId())
}
