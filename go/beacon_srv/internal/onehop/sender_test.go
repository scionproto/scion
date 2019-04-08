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
			IA:  xtest.MustParseIA("1-ff00:0:110"),
			MAC: createMac(t),
		}
		now := time.Now()
		oneHopPath, err := s.CreatePath(12, now)
		SoMsg("err", err, ShouldBeNil)
		path := (*spath.Path)(oneHopPath)

		// Info check
		info, err := path.GetInfoField(path.InfOff)
		SoMsg("InfoErr", err, ShouldBeNil)
		SoMsg("Info.ISD", info.ISD, ShouldEqual, s.IA.I)
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
		SoMsg("Hop.Verify", hop.Verify(s.MAC, info.TsInt, nil), ShouldBeNil)

		// Second hop field set.
		err = path.IncOffsets()
		SoMsg("Path has second hop", err, ShouldBeNil)

		// Path of length 2.
		err = path.IncOffsets()
		SoMsg("Path of length 2", err, ShouldNotBeNil)
	})
}

func TestSenderCreatePkt(t *testing.T) {
	Convey("CreatePkt creates a correct packet", t, func() {
		s := &Sender{
			IA: xtest.MustParseIA("1-ff00:0:110"),
			Addr: &addr.AppAddr{
				L3: addr.HostFromIPStr("127.0.0.1"),
				L4: addr.NewL4UDPInfo(4242),
			},
			MAC: createMac(t),
		}
		msg := &Msg{
			Dst: snet.SCIONAddress{
				IA:   xtest.MustParseIA("1-ff00:0:111"),
				Host: addr.SvcBS,
			},
			Ifid:     12,
			InfoTime: time.Now(),
			Pld:      common.RawBytes{1, 2, 3, 4},
		}
		pkt, err := s.CreatePkt(msg)
		SoMsg("err", err, ShouldBeNil)
		checkTestPkt(t, s, msg, pkt)
	})
}

func TestSenderSend(t *testing.T) {
	Convey("Send sends packet", t, func() {
		wconn, rconn := p2p.NewPacketConns()
		s := &Sender{
			IA:   xtest.MustParseIA("1-ff00:0:110"),
			Conn: snet.NewSCIONPacketConn(wconn),
			Addr: &addr.AppAddr{
				L3: addr.HostFromIPStr("127.0.0.1"),
				L4: addr.NewL4UDPInfo(4242),
			},
			MAC: createMac(t),
		}
		// Read from connection to unblock sender.
		pkt := &snet.SCIONPacket{}
		done := make(chan struct{})
		go func() {
			snet.NewSCIONPacketConn(&testConn{rconn}).ReadFrom(pkt, &overlay.OverlayAddr{})
			close(done)
		}()
		msg := &Msg{
			Dst: snet.SCIONAddress{
				IA:   xtest.MustParseIA("1-ff00:0:111"),
				Host: addr.SvcBS,
			},
			Ifid:     12,
			InfoTime: time.Now(),
			Pld:      common.RawBytes{1, 2, 3, 4},
		}
		err := s.Send(msg, &overlay.OverlayAddr{})
		SoMsg("err", err, ShouldBeNil)
		<-done
		checkTestPkt(t, s, msg, pkt)
	})
}

func checkTestPkt(t *testing.T, s *Sender, msg *Msg, pkt *snet.SCIONPacket) {

	SoMsg("dst", pkt.Destination, ShouldResemble, msg.Dst)
	SoMsg("src", pkt.Source, ShouldResemble, snet.SCIONAddress{
		IA:   s.IA,
		Host: addr.HostFromIPStr("127.0.0.1"),
	})
	SoMsg("exts", pkt.Extensions, ShouldContain, &layers.ExtnOHP{})
	SoMsg("l4", pkt.L4Header.(*l4.UDP).SrcPort, ShouldEqual, 4242)
	SoMsg("pld", pkt.Payload, ShouldResemble, msg.Pld)
	path, err := s.CreatePath(msg.Ifid, msg.InfoTime)
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

func createMac(t *testing.T) hash.Hash {
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	return mac
}
