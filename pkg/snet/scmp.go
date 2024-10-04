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

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers"
)

// RevocationHandler is called by the default SCMP Handler whenever revocations are encountered.
type RevocationHandler interface {
	// RevokeRaw handles a revocation received as raw bytes.
	Revoke(ctx context.Context, revInfo *path_mgmt.RevInfo) error
}

// SCMPHandler customizes the way snet connections deal with SCMP.
type SCMPHandler interface {
	// Handle processes the packet as an SCMP packet. If packet is not SCMP, it
	// returns an error.
	//
	// If the handler returns an error value, snet will propagate the error
	// back to the caller. If the return value is nil, snet will reattempt to
	// read a data packet from the underlying connection.
	//
	// Handlers that wish to ignore SCMP can just return nil.
	//
	// If the handler mutates the packet, the changes are seen by snet
	// connection method callers.
	Handle(pkt *Packet) error
}

// DefaultSCMPHandler handles SCMP messages received from the network. If a
// revocation handler is configured, it is informed of any received interface
// down messages.
type DefaultSCMPHandler struct {
	// RevocationHandler manages revocations received via SCMP. If nil, the
	// handler is not called.
	RevocationHandler RevocationHandler
	// SCMPErrors reports the total number of SCMP Errors encountered.
	SCMPErrors metrics.Counter
}

func (h DefaultSCMPHandler) Handle(pkt *Packet) error {
	scmp, ok := pkt.Payload.(SCMPPayload)
	if !ok {
		return serrors.New("scmp handler invoked with non-scmp packet", "pkt", pkt)
	}
	typeCode := slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code())
	if !typeCode.InfoMsg() {
		metrics.CounterInc(h.SCMPErrors)
	}
	switch scmp.Type() {
	case slayers.SCMPTypeExternalInterfaceDown:
		msg := pkt.Payload.(SCMPExternalInterfaceDown)
		return h.handleSCMPRev(typeCode, &path_mgmt.RevInfo{
			IfID:         iface.ID(msg.Interface),
			RawIsdas:     msg.IA,
			RawTimestamp: util.TimeToSecs(time.Now()),
			RawTTL:       10,
		})
	case slayers.SCMPTypeInternalConnectivityDown:
		msg := pkt.Payload.(SCMPInternalConnectivityDown)
		return h.handleSCMPRev(typeCode, &path_mgmt.RevInfo{
			IfID:         iface.ID(msg.Egress),
			RawIsdas:     msg.IA,
			RawTimestamp: util.TimeToSecs(time.Now()),
			RawTTL:       10,
		})
	default:
		// Only handle connectivity down for now
		log.Debug("Ignoring scmp packet", "scmp", typeCode, "src", pkt.Source)
		return nil
	}
}
func (h *DefaultSCMPHandler) handleSCMPRev(typeCode slayers.SCMPTypeCode,
	revInfo *path_mgmt.RevInfo) error {

	if h.RevocationHandler != nil {
		err := h.RevocationHandler.Revoke(context.TODO(), revInfo)
		if err != nil {
			log.Info("Notifying revocation handler failed", "err", err)
		}
	}
	return &OpError{typeCode: typeCode, revInfo: revInfo}
}

// SCMPPropagationStopper wraps an SCMP handler and stops propagation of the
// SCMP errors up the stack. This can be necessary if the client code aborts on
// unexpected errors. This is a temporary solution until we address
// https://github.com/scionproto/scion/issues/4389.
//
// EXPERIMENTAL: This handler is experimental and may be removed in the future.
type SCMPPropagationStopper struct {
	// Handler is the wrapped handler.
	Handler SCMPHandler
	// Log is an optional function that is called when the wrapped handler
	// returns an error and propagation is stopped.
	Log func(msg string, ctx ...any)
}

func (h SCMPPropagationStopper) Handle(pkt *Packet) error {
	if err := h.Handler.Handle(pkt); err != nil && h.Log != nil {
		h.Log("Stopped SCMP error propagation", "err", err)
	}
	return nil
}
