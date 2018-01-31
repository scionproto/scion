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

// Package ctrl_msg implements a layer for sending SCION Ctrl payload
// requests/notifications via the infra dispatcher, including integrated
// signing and signature verification of ctrl payloads.
package ctrl_msg

import (
	"context"
	"net"

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/proto"
)

type notifyF func(context.Context, disp.Message, net.Addr) error

type Requester struct {
	signer ctrl.Signer
	sigv   ctrl.SigVerifier
	d      *disp.Dispatcher
}

func NewRequester(signer ctrl.Signer, sigv ctrl.SigVerifier, d *disp.Dispatcher) *Requester {
	return &Requester{signer: signer, sigv: sigv, d: d}
}

func (r *Requester) Request(ctx context.Context, pld *ctrl.Pld,
	a net.Addr) (*ctrl.Pld, *proto.SignS, error) {
	spld, err := r.signer.Sign(pld)
	if err != nil {
		return nil, nil, err
	}
	reply, err := r.d.Request(ctx, spld, a)
	if err != nil {
		return nil, nil, err
	}
	rspld, ok := reply.(*ctrl.SignedPld)
	if !ok {
		return nil, nil, common.NewBasicError("ctrl_msg: reply is not a ctrl.SignedPld", nil,
			"type", common.TypeOf(reply), "reply", reply)
	}
	if err := r.sigv.Verify(rspld); err != nil {
		return nil, rspld.Sign, err
	}
	rpld, err := rspld.Pld()
	if err != nil {
		return nil, rspld.Sign, err
	}
	return rpld, rspld.Sign, nil
}

func (r *Requester) Notify(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	return r.notify(ctx, pld, a, r.d.Notify)
}

func (r *Requester) NotifyUnreliable(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	return r.notify(ctx, pld, a, r.d.NotifyUnreliable)
}

func (r *Requester) notify(ctx context.Context, pld *ctrl.Pld, a net.Addr, f notifyF) error {
	spld, err := pld.SignedPld(r.signer)
	if err != nil {
		return err
	}
	return f(ctx, spld, a)
}
