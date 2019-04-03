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

package onehop

import (
	"hash"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

func TestSenderCreatePath(t *testing.T) {
	Convey("Create Path creates a correct path", t, func() {
		s := &Sender{
			SrcIA: xtest.MustParseIA("1-ff00:0:110"),
			HFMacPool: &sync.Pool{
				New: func() interface{} {
					mac, _ := scrypto.InitMac(make(common.RawBytes, 16))
					return mac
				},
			},
		}
		now := time.Now()
		oneHopPath, err := s.CreatePath(12, now)
		SoMsg("err", err, ShouldBeNil)
		path := (*spath.Path)(oneHopPath)

		// Info check
		info, err := path.GetInfoField(path.InfOff)
		SoMsg("InfoErr", err, ShouldBeNil)
		SoMsg("Info.ISD", info.ISD, ShouldEqual, s.SrcIA.I)
		SoMsg("Info.ConsDir", info.ConsDir, ShouldBeTrue)
		SoMsg("Info.Shortcut", info.Shortcut, ShouldBeFalse)
		SoMsg("Info.Peer", info.Peer, ShouldBeFalse)
		SoMsg("Info.TsInt", info.TsInt, ShouldEqual, util.TimeToSecs(now))
		SoMsg("Info.ISD", info.ISD, ShouldEqual, 1)
		SoMsg("Info.Hops", info.Hops, ShouldEqual, 2)

		// Hop check
		hop, err := path.GetHopField(path.HopOff)
		SoMsg("HopErr", err, ShouldBeNil)
		SoMsg("Hop.Xover", hop.Xover, ShouldBeFalse)
		SoMsg("Hop.VerifyOnly", hop.VerifyOnly, ShouldBeFalse)
		SoMsg("Hop.ExpTime", hop.ExpTime, ShouldEqual, spath.DefaultHopFExpiry)
		SoMsg("Hop.ConsIngress", hop.ConsIngress, ShouldEqual, 0)
		SoMsg("Hop.ConsEgress", hop.ConsEgress, ShouldEqual, 12)
		SoMsg("Hop.Verify", hop.Verify(s.HFMacPool.Get().(hash.Hash), info.TsInt, nil), ShouldBeNil)

		// Second hop field set.
		err = path.IncOffsets()
		SoMsg("Path has second hop", err, ShouldBeNil)

		// Path of length 2.
		err = path.IncOffsets()
		SoMsg("Path of length 2", err, ShouldNotBeNil)
	})
}

func TestSenderPkt(t *testing.T) {
	Convey("Pkt creates a correct packet", t, func() {
		s := &Sender{
			SrcIA: xtest.MustParseIA("1-ff00:0:110"),
			Addr: &addr.AppAddr{
				L3: addr.HostFromIPStr("127.0.0.1"),
				L4: addr.NewL4UDPInfo(4242),
			},
			HFMacPool: &sync.Pool{
				New: func() interface{} {
					mac, _ := scrypto.InitMac(make(common.RawBytes, 16))
					return mac
				},
			},
		}
		dst := snet.SCIONAddress{
			IA:   xtest.MustParseIA("1-ff00:0:111"),
			Host: addr.SvcBS,
		}
		now := time.Now()
		pkt, err := s.Pkt(dst, 12, common.RawBytes{1, 2, 3, 4}, now)
		SoMsg("err", err, ShouldBeNil)
		checkTestPkt(t, s, 12, dst, now, common.RawBytes{1, 2, 3, 4}, pkt)
	})
}

func TestSenderSend(t *testing.T) {
	Convey("Send sends packet", t, func() {
		wconn, rconn := p2p.NewPacketConns()
		s := &Sender{
			SrcIA: xtest.MustParseIA("1-ff00:0:110"),
			Conn:  snet.NewSCIONPacketConn(wconn),
			Addr: &addr.AppAddr{
				L3: addr.HostFromIPStr("127.0.0.1"),
				L4: addr.NewL4UDPInfo(4242),
			},
			HFMacPool: &sync.Pool{
				New: func() interface{} {
					mac, _ := scrypto.InitMac(make(common.RawBytes, 16))
					return mac
				},
			},
		}
		// Read from connection to unblock sender.
		pkt := &snet.SCIONPacket{}
		done := make(chan struct{})
		go func() {
			snet.NewSCIONPacketConn(&testConn{rconn}).ReadFrom(pkt, &overlay.OverlayAddr{})
			close(done)
		}()
		// Create and send packet.
		dst := snet.SCIONAddress{
			IA:   xtest.MustParseIA("1-ff00:0:111"),
			Host: addr.SvcBS,
		}
		now := time.Now()
		err := s.Send(dst, 12, &overlay.OverlayAddr{}, common.RawBytes{1, 2, 3, 4}, now)
		SoMsg("err", err, ShouldBeNil)
		<-done
		checkTestPkt(t, s, 12, dst, now, common.RawBytes{1, 2, 3, 4}, pkt)
	})
}

func checkTestPkt(t *testing.T, s *Sender, ifid common.IFIDType, dst snet.SCIONAddress,
	now time.Time, pld common.Payload, pkt *snet.SCIONPacket) {

	SoMsg("dst", pkt.Destination, ShouldResemble, dst)
	SoMsg("src", pkt.Source, ShouldResemble, snet.SCIONAddress{
		IA:   s.SrcIA,
		Host: addr.HostFromIPStr("127.0.0.1"),
	})
	SoMsg("exts", pkt.Extensions, ShouldContain, &layers.ExtnOHP{})
	SoMsg("l4", pkt.L4Header.(*l4.UDP).SrcPort, ShouldEqual, 4242)
	SoMsg("pld", pkt.Payload, ShouldResemble, pld)
	path, err := s.CreatePath(ifid, now)
	xtest.FailOnErr(t, err)
	SoMsg("path", pkt.Path, ShouldResemble, (*spath.Path)(path))
}

// testConn is a packet conn that returns an empty overlay address.
type testConn struct {
	net.PacketConn
}

func (conn *testConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := conn.PacketConn.ReadFrom(b)
	return n, &overlay.OverlayAddr{}, err
}
