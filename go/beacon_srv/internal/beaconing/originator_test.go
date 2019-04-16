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

package beaconing

import (
	"context"
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
	"github.com/scionproto/scion/go/proto"
)

func TestOriginatorRun(t *testing.T) {
	setupItopo(t)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	wconn, rconn := p2p.NewPacketConns()

	signer, err := trust.NewBasicSigner(priv, infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			ChainVer: 42,
			TRCVer:   84,
			IA:       xtest.MustParseIA("1-ff00:0:110"),
		},
		Algo:    scrypto.Ed25519,
		ExpTime: time.Now().Add(time.Hour),
	})
	xtest.FailOnErr(t, err)

	o, err := NewOriginator(intfs,
		Config{
			MTU:    uint16(itopo.Get().MTU),
			Signer: signer,
		},
		&onehop.Sender{
			IA:   xtest.MustParseIA("1-ff00:0:110"),
			Conn: snet.NewSCIONPacketConn(wconn),
			Addr: &addr.AppAddr{
				L3: addr.HostFromIPStr("127.0.0.1"),
				L4: addr.NewL4UDPInfo(4242),
			},
			MAC: mac,
		},
	)
	xtest.FailOnErr(t, err)
	var pkts []*snet.SCIONPacket
	Convey("Run originates ifid packets on all core and child interfaces", t, func() {
		done := make(chan struct{})
		// Read packets from the connection to unblock sender.
		go func() {
			conn := snet.NewSCIONPacketConn(&testConn{rconn})
			for range itopo.Get().IFInfoMap {
				pkt := &snet.SCIONPacket{}
				conn.ReadFrom(pkt, &overlay.OverlayAddr{})
				pkts = append(pkts, pkt)
			}
			close(done)
		}()
		intfs.Get(1129).Activate(82)
		intfs.Get(42).Activate(84)
		// Start beacon messages.
		o.Run(nil)
		<-done
		SoMsg("Pkts", len(pkts), ShouldEqual, len(itopo.Get().IFInfoMap))
		for _, pkt := range pkts {
			// Extract segment from the payload
			spld, err := ctrl.NewSignedPldFromRaw(pkt.Payload.(common.RawBytes))
			SoMsg("SPldErr", err, ShouldBeNil)
			pld, err := spld.UnsafePld()
			SoMsg("PldErr", err, ShouldBeNil)
			err = pld.Beacon.Parse()
			SoMsg("ParseErr", err, ShouldBeNil)

			// Check the as entry is verifiable and the source is set correctly.
			err = pld.Beacon.Segment.VerifyASEntry(context.Background(), segVerifier(pub), 0)
			SoMsg("VerifyErr", err, ShouldBeNil)
			src, err := ctrl.NewSignSrcDefFromRaw(spld.Sign.Src)
			SoMsg("Src err", err, ShouldBeNil)
			SoMsg("Src.IA", src.IA, ShouldResemble, xtest.MustParseIA("1-ff00:0:110"))
			SoMsg("Src.ChainVer", src.ChainVer, ShouldEqual, 42)
			SoMsg("Src.TrcVer", src.TRCVer, ShouldEqual, 84)

			// Check the AS entry is set correctly.
			entry := pld.Beacon.Segment.ASEntries[0]
			SoMsg("ChainVer", entry.CertVer, ShouldEqual, 42)
			SoMsg("TRCVer", entry.TrcVer, ShouldEqual, 84)
			SoMsg("IfIDSize", entry.IfIDSize, ShouldEqual, DefaultIfidSize)
			SoMsg("MTU", entry.MTU, ShouldEqual, itopo.Get().MTU)
			SoMsg("IA", entry.IA(), ShouldResemble, o.sender.IA)
			SoMsg("HopEntries length", len(entry.HopEntries), ShouldEqual, 1)
			hop := entry.HopEntries[0]

			// Check the hop field is set correctly.
			hopF, err := spath.HopFFromRaw(hop.RawHopField)
			SoMsg("Parse hop field", err, ShouldBeNil)
			infoF, err := pld.Beacon.Segment.InfoF()
			SoMsg("Parse info field", err, ShouldBeNil)
			SoMsg("hopF.ConsIngress", hopF.ConsIngress, ShouldBeZeroValue)
			SoMsg("hopF.Mac", hopF.Verify(o.sender.MAC, infoF.TsInt, nil), ShouldBeNil)
			expiry, err := spath.ExpTimeFromDuration(
				signer.Meta().ExpTime.Sub(infoF.Timestamp()), false)
			xtest.FailOnErr(t, err)
			SoMsg("hopF.ExpTime", hopF.ExpTime, ShouldEqual, expiry)

			// Check the hop entry is set correctly.
			intf := intfs.Get(hopF.ConsEgress)
			SoMsg("Intf exists", intf, ShouldNotBeNil)
			SoMsg("Hop.InIA", hop.InIA(), ShouldResemble, addr.IA{})
			SoMsg("Hop.InIf", hop.RemoteInIF, ShouldBeZeroValue)
			SoMsg("hop.InMTU", hop.InMTU, ShouldBeZeroValue)
			SoMsg("Hop.OutIA", hop.OutIA(), ShouldResemble, intf.TopoInfo().ISD_AS)
			SoMsg("Hop.OutIf", hop.RemoteOutIF, ShouldResemble, intf.TopoInfo().RemoteIFID)

		}
	})
}

func setupItopo(t *testing.T) {
	itopo.Init("", proto.ServiceType_unset, itopo.Callbacks{})
	topo, err := topology.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	_, _, err = itopo.SetStatic(topo, true)
	xtest.FailOnErr(t, err)
}

type segVerifier common.RawBytes

func (v segVerifier) Verify(_ context.Context, msg common.RawBytes, sign *proto.SignS) error {
	return scrypto.Verify(sign.SigInput(msg, false), sign.Signature,
		common.RawBytes(v), scrypto.Ed25519)
}

// testConn is a packet conn that returns an empty overlay address.
type testConn struct {
	net.PacketConn
}

func (conn *testConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := conn.PacketConn.ReadFrom(b)
	return n, &overlay.OverlayAddr{}, err
}
