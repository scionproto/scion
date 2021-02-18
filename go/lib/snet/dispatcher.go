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
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/snet/internal/metrics"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/util"
)

// PacketDispatcherService constructs SCION sockets where applications have
// fine-grained control over header fields.
type PacketDispatcherService interface {
	Register(ctx context.Context, ia addr.IA, registration *net.UDPAddr,
		svc addr.HostSVC) (PacketConn, uint16, error)
}

var _ PacketDispatcherService = (*DefaultPacketDispatcherService)(nil)

// DefaultPacketDispatcherService parses/serializes packets received from /
// sent to the dispatcher.
type DefaultPacketDispatcherService struct {
	// Dispatcher is used to get packets from the local SCION Dispatcher process.
	Dispatcher reliable.Dispatcher
	// SCMPHandler is invoked for packets that contain an SCMP L4. If the
	// handler is nil, errors are returned back to applications every time an
	// SCMP message is received.
	SCMPHandler SCMPHandler
}

func (s *DefaultPacketDispatcherService) Register(ctx context.Context, ia addr.IA,
	registration *net.UDPAddr, svc addr.HostSVC) (PacketConn, uint16, error) {

	rconn, port, err := s.Dispatcher.Register(ctx, ia, registration, svc)
	if err != nil {
		return nil, 0, err
	}
	return &SCIONPacketConn{
		conn:        rconn,
		scmpHandler: s.SCMPHandler,
	}, port, nil
}

// RevocationHandler is called by the default SCMP Handler whenever revocations are encountered.
type RevocationHandler interface {
	// RevokeRaw handles a revocation received as raw bytes.
	RevokeRaw(ctx context.Context, rawSRevInfo []byte)
}

// SCMPHandler customizes the way snet connections deal with SCMP.
type SCMPHandler interface {
	// Handle processes the packet as an SCMP packet. If packet is not SCMP, it
	// returns an error.
	//
	// If the handler returns an error value, snet will propagate the error
	// back to the caller. If the return value is nil, snet will reattempt to
	// read a data packet from the underlying dispatcher connection.
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
}

func (h DefaultSCMPHandler) Handle(pkt *Packet) error {
	scmp, ok := pkt.Payload.(SCMPPayload)
	if !ok {
		return serrors.New("scmp handler invoked with non-scmp packet", "pkt", pkt)
	}
	typeCode := slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code())
	if !typeCode.InfoMsg() {
		metrics.M.SCMPErrors().Inc()
	}
	switch scmp.Type() {
	case slayers.SCMPTypeExternalInterfaceDown:
		msg := pkt.Payload.(SCMPExternalInterfaceDown)
		return h.handleSCMPRev(typeCode, &path_mgmt.RevInfo{
			IfID:         common.IFIDType(msg.Interface),
			RawIsdas:     msg.IA.IAInt(),
			RawTimestamp: util.TimeToSecs(time.Now()),
			RawTTL:       10,
		})
	case slayers.SCMPTypeInternalConnectivityDown:
		msg := pkt.Payload.(SCMPInternalConnectivityDown)
		return h.handleSCMPRev(typeCode, &path_mgmt.RevInfo{
			IfID:         common.IFIDType(msg.Egress),
			RawIsdas:     msg.IA.IAInt(),
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

	sRev, err := path_mgmt.NewSignedRevInfo(revInfo)
	if err != nil {
		return serrors.WrapStr("creating signed rev info", err)
	}
	raw, err := sRev.Pack()
	if err != nil {
		return serrors.WrapStr("packing signed rev info", err)
	}
	if h.RevocationHandler != nil {
		h.RevocationHandler.RevokeRaw(context.TODO(), raw)
	}
	return &OpError{typeCode: typeCode, revInfo: revInfo}
}
