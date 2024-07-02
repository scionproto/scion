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

package snet

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
)

// RevocationHandler is called by the default SCMP Handler whenever revocations are encountered.
type RevocationHandler interface {
	// RevokeRaw handles a revocation received as raw bytes.
	Revoke(ctx context.Context, revInfo *path_mgmt.RevInfo) error
}

// SCMPHandler customizes the way snet.Conn deals with SCMP messages during Read/ReadFrom.
type SCMPHandler interface {
	// Handle processes the packet as an SCMP packet.
	//
	// If the handler returns an error, snet.Conn.Read/ReadFrom will
	// abort and propagate the error back to the caller.
	// A packet that is not an SCMP or that is otherwise invalid or unexpected
	// should be ignored without error.
	Handle(pkt *Packet) error
}

// DefaultSCMPHandler handles SCMP messages received from the network. If a
// revocation handler is configured, it is informed of any received interface
// down messages.
// It never returns an error "in line", so snet.Conn.Read/ReadFrom will not be
// aware of SCMP errors. Use the RevocationHandler to react to path failures.
type DefaultSCMPHandler struct {
	// RevocationHandler manages revocations received via SCMP. If nil, the
	// handler is not called.
	RevocationHandler RevocationHandler
	// SCMPErrors reports the total number of SCMP Error messages encountered.
	SCMPErrors metrics.Counter
	// Log is an optional function that is used to log SCMP messages
	// TODO log...
	Log func(msg string, ctx ...any)
}

func (h DefaultSCMPHandler) Handle(pkt *Packet) error {
	scmp, ok := pkt.Payload.(SCMPPayload)
	if !ok {
		return nil
	}
	typeCode := slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code())
	if !typeCode.InfoMsg() {
		metrics.CounterInc(h.SCMPErrors)
	}
	switch scmp.Type() {
	case slayers.SCMPTypeExternalInterfaceDown:
		msg := pkt.Payload.(SCMPExternalInterfaceDown)
		h.handleSCMPRev(&path_mgmt.RevInfo{
			IfID:         common.IFIDType(msg.Interface),
			RawIsdas:     msg.IA,
			RawTimestamp: util.TimeToSecs(time.Now()),
			RawTTL:       10,
		})
	case slayers.SCMPTypeInternalConnectivityDown:
		msg := pkt.Payload.(SCMPInternalConnectivityDown)
		h.handleSCMPRev(&path_mgmt.RevInfo{
			IfID:         common.IFIDType(msg.Egress),
			RawIsdas:     msg.IA,
			RawTimestamp: util.TimeToSecs(time.Now()),
			RawTTL:       10,
		})
	default:
		h.log("Ignoring SCMP packet", "scmp", typeCode, "src", pkt.Source)
	}
	return nil
}

func (h DefaultSCMPHandler) log(msg string, ctx ...any) {
	if h.Log == nil {
		return
	}
	h.Log(msg, ctx)
}

// TODO: matzf replace RevocationHandler interface with something that does not rely on ancient RevInfo struct
func (h *DefaultSCMPHandler) handleSCMPRev(revInfo *path_mgmt.RevInfo) error {

	if h.RevocationHandler != nil {
		return h.RevocationHandler.Revoke(context.TODO(), revInfo)
	}
	return nil
}
