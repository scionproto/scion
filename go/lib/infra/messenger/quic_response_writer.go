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

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/rpc"
)

var _ infra.ResponseWriter = (*QUICResponseWriter)(nil)

// QUICResponseWriter implements the infra ResponseWriter over QUIC.
type QUICResponseWriter struct {
	ReplyWriter rpc.ReplyWriter
	ID          uint64
}

func (rw *QUICResponseWriter) SendAckReply(ctx context.Context, msg *ack.Ack) error {
	go func() {
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPld(msg, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{SignedPld: signedCtrlPld})
}

func (rw *QUICResponseWriter) SendTRCReply(ctx context.Context, msg *cert_mgmt.TRC) error {
	go func() {
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{SignedPld: signedCtrlPld})
}

func (rw *QUICResponseWriter) SendCertChainReply(ctx context.Context, msg *cert_mgmt.Chain) error {
	go func() {
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{SignedPld: signedCtrlPld})
}

func (rw *QUICResponseWriter) SendChainIssueReply(ctx context.Context,
	msg *cert_mgmt.ChainIssRep) error {

	go func() {
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{SignedPld: signedCtrlPld})
}

func (rw *QUICResponseWriter) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply) error {
	go func() {
		<-ctx.Done()
		rw.ReplyWriter.Close()
	}()
	ctrlPld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: rw.ID})
	if err != nil {
		return err
	}
	signedCtrlPld, err := ctrlPld.SignedPld(infra.NullSigner)
	if err != nil {
		return err
	}
	return rw.ReplyWriter.WriteReply(&rpc.Reply{SignedPld: signedCtrlPld})
}
