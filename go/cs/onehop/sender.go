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

// Package onehop provides a sender for messages sent on a one-hop path.
package onehop

import (
	"context"
	"hash"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// Path is a one-hop path.
type Path spath.Path

// Msg defines the message payload and the path it is sent on.
type Msg struct {
	// Dst is the destination of the message.
	Dst snet.SCIONAddress
	// Ifid is the IFID the message is sent on.
	Ifid common.IFIDType
	// InfoTime is the timestamp set in the info field.
	InfoTime time.Time
	// Pld is the message payload.
	Pld []byte
}

// Sender is used to send payloads on a one-hop path.
type Sender struct {
	// IA is the ISD-AS of the local AS.
	IA addr.IA
	// Addr is the address that is set as the source.
	Addr *net.UDPAddr
	// Conn is used to send the packets.
	Conn snet.PacketConn
	// macMtx protects the MAC.
	macMtx sync.Mutex
	// MAC is the mac to issue hop fields.
	MAC hash.Hash
}

// Send sends the payload on a one-hop path.
func (s *Sender) Send(msg *Msg, nextHop *net.UDPAddr) error {
	pkt, err := s.CreatePkt(msg)
	if err != nil {
		return common.NewBasicError("Unable to create packet", err)
	}
	return s.Conn.WriteTo(pkt, nextHop)
}

// CreatePkt creates a scion packet with a one-hop path and the payload.
func (s *Sender) CreatePkt(msg *Msg) (*snet.Packet, error) {
	path, err := s.CreatePath(msg.Ifid, msg.InfoTime)
	if err != nil {
		return nil, err
	}
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: msg.Dst,
			Source: snet.SCIONAddress{
				IA:   s.IA,
				Host: addr.HostFromIP(s.Addr.IP),
			},
			Path: (spath.Path)(path),
			Payload: snet.UDPPayload{
				SrcPort: uint16(s.Addr.Port),
				Payload: msg.Pld,
			},
		},
	}
	return pkt, nil
}

// CreatePath creates the one-hop path and initializes it.
func (s *Sender) CreatePath(ifid common.IFIDType, now time.Time) (Path, error) {
	s.macMtx.Lock()
	defer s.macMtx.Unlock()

	path, err := spath.NewOneHop(s.IA.I, uint16(ifid), now, 63, s.MAC)
	if err != nil {
		return Path{}, err
	}
	return (Path)(path), nil
}

// RPC is used to send beacons.
type RPC interface {
	SendBeacon(ctx context.Context, b *seg.PathSegment, remote net.Addr) error
}

// BeaconSender is used to send beacons on a one-hop path.
type BeaconSender struct {
	Sender
	// AddressRewriter resolves SVC addresses, if possible. If it is nil,
	// resolution is not attempted.
	AddressRewriter *messenger.AddressRewriter
	RPC             RPC
}

// Send packs and sends out the beacon.
func (s *BeaconSender) Send(ctx context.Context, bseg *seg.PathSegment, ia addr.IA,
	egIfid common.IFIDType, ov *net.UDPAddr) error {

	path, err := s.CreatePath(egIfid, time.Now())
	if err != nil {
		return err
	}

	svc := &snet.SVCAddr{
		IA:      ia,
		Path:    (spath.Path)(path),
		NextHop: ov,
		SVC:     addr.SvcCS,
	}
	addr, redirect, err := s.AddressRewriter.RedirectToQUIC(ctx, svc)
	if err != nil {
		return serrors.WrapStr("resolving service", err)
	}
	if !redirect {
		return serrors.New("could not resolve QUIC", "addr", svc)
	}
	log.Debug("Beaconing upgraded to QUIC", "remote", addr)
	if err := s.RPC.SendBeacon(ctx, bseg, addr); err != nil {
		return serrors.WrapStr("sending beacon", err)
	}
	return nil
}
