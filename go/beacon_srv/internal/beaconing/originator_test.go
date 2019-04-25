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
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
	"github.com/scionproto/scion/go/proto"
)

const (
	topoCore    = "testdata/topology-core.json"
	topoNonCore = "testdata/topology.json"
)

func TestOriginatorRun(t *testing.T) {
	setupItopo(t, topoCore)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := testSigner(t, priv)
	Convey("Run originates ifid packets on all active core and child interfaces", t, func() {
		wconn, rconn := p2p.NewPacketConns()
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
		intfs.Get(1129).Activate(82)
		intfs.Get(42).Activate(84)
		stop := make(chan struct{})
		done := readTestPkts(stop, rconn, 2)
		// Start beacon messages.
		o.Run(nil)
		var pkts []*snet.SCIONPacket
		select {
		case pkts = <-done:
		case <-time.After(1 * time.Second):
			SoMsg("Timed out", true, ShouldBeFalse)
		}
		SoMsg("Pkts", len(pkts), ShouldEqual, len(itopo.Get().IFInfoMap))
		for i, pkt := range pkts {
			Convey(fmt.Sprintf("Packet %d is correct", i), func() {
				// Extract segment from the payload
				spld, err := ctrl.NewSignedPldFromRaw(pkt.Payload.(common.RawBytes))
				SoMsg("SPldErr", err, ShouldBeNil)
				pld, err := spld.UnsafePld()
				SoMsg("PldErr", err, ShouldBeNil)
				err = pld.Beacon.Parse()
				SoMsg("ParseErr", err, ShouldBeNil)
				Convey("Segment can be validated", func() {
					err = pld.Beacon.Segment.Validate(seg.ValidateBeacon)
					SoMsg("err", err, ShouldBeNil)
				})
				Convey("Segment can be verified", func() {
					err = pld.Beacon.Segment.VerifyASEntry(context.Background(),
						segVerifier(pub), 0)
					SoMsg("err", err, ShouldBeNil)
				})
			})
		}
	})
}

func testTopo(t *testing.T, fn string) *topology.Topo {
	topo, err := topology.LoadFromFile(fn)
	xtest.FailOnErr(t, err)
	return topo
}

func setupItopo(t *testing.T, fn string) {
	itopo.TestingInit(t, "", proto.ServiceType_unset, itopo.Callbacks{})
	_, _, err := itopo.SetStatic(testTopo(t, fn), true)
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

func readTestPkts(stop chan struct{}, rconn net.PacketConn,
	expected int) chan []*snet.SCIONPacket {

	done := make(chan []*snet.SCIONPacket)
	read := make(chan *snet.SCIONPacket)
	// Read packets from connection.
	go func() {
		conn := snet.NewSCIONPacketConn(&testConn{rconn})
		for {
			select {
			case <-stop:
				return
			default:
				pkt := &snet.SCIONPacket{}
				conn.ReadFrom(pkt, &overlay.OverlayAddr{})
				read <- pkt
			}
		}
	}()
	// Return the expected packets. Any subsequent packet fails the test.
	go func() {
		pkts := make([]*snet.SCIONPacket, 0, expected)
		recv := 0
		for {
			select {
			case <-stop:
				return
			case pkt := <-read:
				recv++
				if recv <= expected {
					pkts = append(pkts, pkt)
					if recv == expected {
						done <- pkts
						close(done)
					}
					break
				}
				err := common.NewBasicError("Received unexpected packet", nil,
					"recv", recv, "pkt", pkt)
				SoMsg("Err", err, ShouldNotBeNil)
			}
		}
	}()
	return done
}
