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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet/internal/metrics"
	"github.com/scionproto/scion/go/lib/sock/reliable"
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
	return &SCIONPacketConn{conn: rconn, scmpHandler: s.SCMPHandler}, port, nil
}

// RevocationHandler is called by the default SCMP Handler whenever revocations are encountered.
type RevocationHandler interface {
	// RevokeRaw handles a revocation received as raw bytes.
	RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes)
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

// NewSCMPHandler creates a default SCMP handler that forwards revocations to the revocation
// handler. SCMP packets are also forwarded to snet callers via errors returned by Read calls.
//
// If the revocation handler is nil, revocations are not forwarded. However, they are still sent
// back to the caller during read operations.
func NewSCMPHandler(rh RevocationHandler) SCMPHandler {
	return &scmpHandler{
		revocationHandler: rh,
	}
}

// scmpHandler handles SCMP messages received from the network. If a revocation handler is
// configured, it is informed of any received revocations. All revocations are passed back to the
// caller embedded in the error, so applications can handle them manually.
type scmpHandler struct {
	// revocationHandler manages revocations received via SCMP. If nil, the handler is not called.
	revocationHandler RevocationHandler
}

func (h *scmpHandler) Handle(pkt *Packet) error {
	hdr, ok := pkt.L4Header.(*scmp.Hdr)
	if !ok {
		return common.NewBasicError("scmp handler invoked with non-scmp packet", nil, "pkt", pkt)
	}
	if hdr.Class != scmp.C_General {
		metrics.M.SCMPErrors().Inc()
	}
	if hdr.Class == scmp.C_General && hdr.Type == scmp.T_G_Unspecified {
		// SCMP::General::Unspecified is used for errors
		metrics.M.SCMPErrors().Inc()
	}

	// Only handle revocations for now
	if hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF {
		return h.handleSCMPRev(hdr, pkt)
	}
	log.Debug("Ignoring scmp packet", "hdr", hdr, "src", pkt.Source)
	return nil
}

func (h *scmpHandler) handleSCMPRev(hdr *scmp.Hdr, pkt *Packet) error {
	scmpPayload, ok := pkt.Payload.(*scmp.Payload)
	if !ok {
		return common.NewBasicError("Unable to type assert payload to SCMP payload", nil,
			"type", common.TypeOf(pkt.Payload))
	}
	info, ok := scmpPayload.Info.(*scmp.InfoRevocation)
	if !ok {
		return common.NewBasicError("Unable to type assert SCMP Info to SCMP Revocation Info", nil,
			"type", common.TypeOf(scmpPayload.Info))
	}
	log.Info("Received SCMP revocation", "header", hdr.String(), "payload", scmpPayload.String(),
		"src", pkt.Source)
	if h.revocationHandler != nil {
		h.revocationHandler.RevokeRaw(context.TODO(), info.RawSRev)
	}
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(info.RawSRev)
	if err != nil {
		return err
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		return err
	}
	return &OpError{scmp: hdr, revInfo: revInfo}
}
