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
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/slayers"
)

// RevocationHandler is called by the default SCMP Handler whenever path
// revocations are encountered.
type RevocationHandler interface {
	// Revoke is called by the default SCMP handler whenever revocations (SCMP
	// error messages "external interface down" and "internal connectivity down") are
	// encountered.
	// For "internal connectivity down", both ingress and egress interface values are defined.
	// For "external interface down", ingress is set to 0 and egress is the affected interface.
	//
	// This is called in the packet receive loop and thus expensive blocking
	// operations should be avoided or be triggered asynchronously.
	//
	// If the handler returns an error, snet.Conn.Read/ReadFrom will abort and
	// propagate the error back to the caller.
	Revoke(ia addr.IA, ingress, egress uint64) error
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
	if h.RevocationHandler == nil {
		h.log("Ignoring SCMP packet", "scmp", typeCode, "src", pkt.Source)
		return nil
	}

	// Handle revocation
	switch scmp.Type() {
	case slayers.SCMPTypeExternalInterfaceDown:
		msg := pkt.Payload.(SCMPExternalInterfaceDown)
		h.log("Handling SCMP ExternalInteraceDown",
			"isd_as", msg.IA, "interface", msg.Interface)
		return h.RevocationHandler.Revoke(msg.IA, 0, msg.Interface)
	case slayers.SCMPTypeInternalConnectivityDown:
		msg := pkt.Payload.(SCMPInternalConnectivityDown)
		h.log("Handling SCMP InternalConnectivityDown",
			"isd_as", msg.IA, "ingress", msg.Ingress, "egress", msg.Egress)
		return h.RevocationHandler.Revoke(msg.IA, msg.Ingress, msg.Egress)
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
