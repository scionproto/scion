// Copyright 2017 ETH Zurich
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

// Package api handles CtrlPld message exchanges. Sent and received messages
// must be one of the supported types below.
//
// The API converts all supported types to and from SignedCtrlPld messages.
//
// The following messages are currently supported:
//  cert_mgmt.ChainReq
//  cert_mgmt.Chain
//  cert_mgmt.TRCReq
//  cert_mgmt.TRC
//
// Support will be added for the following messages:
//  seg.PathSegment
//  ifid.IFID
//  path_mgmt.SegReq
//  path_mgmt.SegReply
//  path_mgmt.SegReg
//  path_mgmt.SegRecs
//  path_mgmt.RevInfo
//  path_mgmt.IFStateReq
//  path_mgmt.IFStateInfos
//
// The word "reliable" in method descriptions means a reliable protocol is used
// to deliver that message.
package api

import (
	"context"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/proto"
)

var (
	// MessengerContextKey is a context key. It can be used in SCION infra
	// request handlers to access the messaging layer the message arrived on.
	MessengerContextKey = &contextKey{"infra-messenger"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "infra/api context value " + k.name
}

// A Messenger exposes the API for sending and receiving CtrlPld messages.
type Messenger struct {
	dispatcher *disp.Dispatcher
}

// New creates a new Messenger that uses dispatcher for sending and receiving
// messages.
func New(dispatcher *disp.Dispatcher) *Messenger {
	return &Messenger{
		dispatcher: dispatcher,
	}
}

// RecvMsg reads a new message from the dispatcher.
func (m *Messenger) RecvMsg(ctx context.Context) (interface{}, net.Addr, error) {
	ctrlPldMsg, address, err := m.dispatcher.RecvFrom(ctx)
	if err != nil {
		return nil, nil, err
	}
	msg, err := extractMessage(ctrlPldMsg)
	if err != nil {
		return nil, nil, err
	}
	return msg, address, nil
}

// GetTRC sends a cert_mgmt.TRCReq request to address a, blocks until it receives a
// reply and returns the reply.
func (m *Messenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr) (*cert_mgmt.TRC, error) {
	ctrlPldMsg, err := ctrl.NewCertMgmtPld(msg)
	if err != nil {
		return nil, err
	}
	// Send request and get reply
	replyCtrlPldMsg, err := m.dispatcher.Request(ctx, ctrlPldMsg, a)
	if err != nil {
		return nil, err
	}
	replyMsg, err := extractMessage(replyCtrlPldMsg)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*cert_mgmt.TRC)
	if !ok {
		return nil, newTypeAssertErr("*cert_mgmt.TRC", replyMsg)
	}
	return reply, nil
}

// SendTRC sends a reliable cert_mgmt.TRC to address a.
func (m *Messenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr) error {
	ctrlPldMsg, err := ctrl.NewCertMgmtPld(msg)
	if err != nil {
		return err
	}
	err = m.dispatcher.Notify(ctx, ctrlPldMsg, a)
	if err != nil {
		return err
	}
	return nil
}

// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
// receives a reply and returns the reply.
func (m *Messenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr) (*cert_mgmt.Chain, error) {
	ctrlPldMsg, err := ctrl.NewCertMgmtPld(msg)
	if err != nil {
		return nil, err
	}
	// Send request and get reply
	replyCtrlPldMsg, err := m.dispatcher.Request(ctx, ctrlPldMsg, a)
	if err != nil {
		return nil, err
	}
	replyMsg, err := extractMessage(replyCtrlPldMsg)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*cert_mgmt.Chain)
	if !ok {
		return nil, newTypeAssertErr("*cert_mgmt.Chain", replyMsg)
	}
	return reply, nil
}

// SendCertChain sends a reliable cert_mgmt.Chain to address a.
func (m *Messenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr) error {
	ctrlPldMsg, err := ctrl.NewCertMgmtPld(msg)
	if err != nil {
		return err
	}
	err = m.dispatcher.Notify(ctx, ctrlPldMsg, a)
	if err != nil {
		return err
	}
	return nil
}

// extractMessage flattens all possible ctrlPld messages to a single set of
// directly comparable message types.
func extractMessage(msg disp.Message) (interface{}, error) {
	ctrlPld, ok := msg.(*ctrl.Pld)
	if !ok {
		return nil, newTypeAssertErr("*ctrl.Pld", msg)
	}
	switch ctrlPld.Which {
	case proto.CtrlPld_Which_certMgmt:
		// Extract cert mgmt message
		innerPld := ctrlPld.CertMgmt
		switch innerPld.Which {
		case proto.CertMgmt_Which_trcReq:
			return innerPld.TRCReq, nil
		case proto.CertMgmt_Which_trc:
			return innerPld.TRCRep, nil
		case proto.CertMgmt_Which_certChainReq:
			return innerPld.ChainReq, nil
		case proto.CertMgmt_Which_certChain:
			return innerPld.ChainRep, nil
		default:
			return nil, common.NewCError("Invalid CtrlPld.CertMgmt type", "type", innerPld.Which)
		}
	// FIXME(scrye): add support for CtrlPld.PathMgmt messages; currently these
	// get passed as a top-level message for which no handling exists in the
	// server
	default:
		return ctrlPld, nil
	}
}

func newTypeAssertErr(typeStr string, msg interface{}) error {
	errStr := fmt.Sprintf("Unable to type assert disp.Message to %s", typeStr)
	return common.NewCError(errStr, "msg", msg)
}
