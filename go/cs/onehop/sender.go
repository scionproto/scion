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
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// QUICBeaconSender is used to send beacons over QUIC.
type QUICBeaconSender interface {
	// SendBeacon sends the beacon to the address using the specified ID.
	SendBeacon(ctx context.Context, msg *seg.Beacon, a net.Addr, id uint64) error
}

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
	Pld common.Payload
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
			Path:       (*spath.Path)(path),
			Extensions: []common.Extension{&layers.ExtnOHP{}},
			L4Header: &l4.UDP{
				SrcPort: uint16(s.Addr.Port),
			},
			Payload: msg.Pld,
		},
	}
	return pkt, nil
}

// CreatePath creates the one-hop path and initializes it.
func (s *Sender) CreatePath(ifid common.IFIDType, now time.Time) (*Path, error) {
	s.macMtx.Lock()
	defer s.macMtx.Unlock()
	path := spath.NewOneHop(s.IA.I, ifid, now, spath.DefaultHopFExpiry, s.MAC)
	return (*Path)(path), path.InitOffsets()
}

// BeaconSender is used to send beacons on a one-hop path.
type BeaconSender struct {
	Sender
	// AddressRewriter resolves SVC addresses, if possible. If it is nil,
	// resolution is not attempted.
	AddressRewriter *messenger.AddressRewriter
	// QUICBeaconSender is used to send beacons over QUIC whenever the sender
	// detects that the server supports QUIC.
	QUICBeaconSender QUICBeaconSender
}

// Send packs and sends out the beacon. QUIC is first attempted, and if that
// fails the method falls back on UDP.
func (s *BeaconSender) Send(ctx context.Context, bseg *seg.Beacon, ia addr.IA,
	egIfid common.IFIDType, signer infra.Signer, ov *net.UDPAddr) error {

	path, err := s.CreatePath(egIfid, time.Now())
	if err != nil {
		return err
	}

	quicOk, err := s.attemptQUIC(ctx, ia, (*spath.Path)(path), ov, bseg)
	if err != nil {
		return err
	}
	if quicOk {
		// RPC already handled by QUIC
		return nil
	}

	pld, err := ctrl.NewPld(bseg, nil)
	if err != nil {
		return common.NewBasicError("Unable to create payload", err)
	}
	spld, err := pld.SignedPld(signer)
	if err != nil {
		return common.NewBasicError("Unable to sign payload", err)
	}
	packed, err := spld.PackPld()
	if err != nil {
		return common.NewBasicError("Unable to pack payload", err)
	}
	msg := &Msg{
		Dst: snet.SCIONAddress{
			IA:   ia,
			Host: addr.SvcBS,
		},
		Ifid:     egIfid,
		InfoTime: time.Now(),
		Pld:      packed,
	}
	return s.Sender.Send(msg, ov)
}

func (s *BeaconSender) attemptQUIC(ctx context.Context, ia addr.IA, path *spath.Path,
	nextHop *net.UDPAddr, bseg *seg.Beacon) (bool, error) {

	if s.AddressRewriter == nil {
		return false, nil
	}

	t := &snet.SVCAddr{IA: ia, Path: path, NextHop: nextHop, SVC: addr.SvcBS}
	newAddr, redirect, err := s.AddressRewriter.RedirectToQUIC(ctx, t)

	if err != nil || !redirect {
		log.Trace("Beaconing could not be upgraded to QUIC, using UDP", "remote", newAddr)
		return false, nil
	}
	log.Trace("Beaconing upgraded to QUIC", "remote", newAddr)

	err = s.QUICBeaconSender.SendBeacon(ctx, bseg, newAddr, messenger.NextId())
	return true, err
}
