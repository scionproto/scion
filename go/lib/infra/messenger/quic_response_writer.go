// Copyright 2019 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/rpc"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

var _ infra.ResponseWriter = (*QUICResponseWriter)(nil)

// QUICResponseWriter implements the infra ResponseWriter over QUIC.
type QUICResponseWriter struct {
	ReplyWriter rpc.ReplyWriter
	ID          uint64
}

func (rw *QUICResponseWriter) SendAckReply(ctx context.Context, msg *ack.Ack) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPld(msg, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendTRCReply(ctx context.Context, msg *cert_mgmt.TRC) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendCertChainReply(ctx context.Context, msg *cert_mgmt.Chain) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendChainIssueReply(ctx context.Context,
	msg *cert_mgmt.ChainIssRep) error {

	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendIfStateInfoReply(ctx context.Context,
	msg *path_mgmt.IFStateInfos) error {

	// FIXME(scrye): Use only UDP because the BR doesn't support QUIC.
	return serrors.New("IFStateInfos responses not supported in QUIC")
}

func (rw *QUICResponseWriter) SendHPSegReply(ctx context.Context, msg *path_mgmt.HPSegReply) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) SendHPCfgReply(ctx context.Context, msg *path_mgmt.HPCfgReply) error {
	go func() {
		defer log.LogPanicAndExit()
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	return rw.sendMessage(ctrlPld)
}

func (rw *QUICResponseWriter) sendMessage(ctrlPld *ctrl.Pld) error {
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	msg, err := SignedPldToMsg(signedCtrlPld)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{Message: msg})
}
