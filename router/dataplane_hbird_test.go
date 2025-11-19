// Copyright 2025 ETH Zurich
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

package router_test

import (
	"crypto/aes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
)

func TestDataPlaneSetHbirdKey(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := router.NewDPRaw(router.RunConfig{}, false)
		d.MockStart()
		assert.Error(t, d.SetHbirdKey([]byte("dummy")))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := router.NewDPRaw(router.RunConfig{}, false)
		d.MockStart()
		assert.Error(t, d.SetHbirdKey(nil))
	})
	t.Run("single set works", func(t *testing.T) {
		d := router.NewDPRaw(router.RunConfig{}, false)
		assert.NoError(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
	})
	t.Run("double set fails", func(t *testing.T) {
		d := router.NewDPRaw(router.RunConfig{}, false)
		assert.NoError(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
		assert.Error(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
	})
}

func TestProcessHbirdPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	otherKey := []byte("testkey_yyyyyyyy")
	hbirdKey := []byte("test_secretvalue")
	now := time.Now()
	// now := time.Date(2025, 1, 1, 1, 1, 1, 1, time.UTC) // deleteme

	// ProcessPacket assumes some pre-conditions:
	// * The ingress interface has to exist. This mock map is good for most test cases.
	//   Others need a custom one.
	// * InternalNextHops may not be nil. Empty is ok (sufficient unless testing AS transit).
	mockExternalInterfaces := []uint16{1, 2, 3}
	mockInternalNextHops := map[uint16]netip.AddrPort{}

	testCases := map[string]struct {
		prepareDP  func(*gomock.Controller) *router.DataPlane
		mockMsg    func(bool, *router.DataPlane) *router.Packet
		assertFunc func(*testing.T, router.Disposition)
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				assert.NoError(t, spkt.SetDstAddr(dst))
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
				}
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.HopFields[0].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.CurrHF = 3
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.CurrHF = 3
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					egress = 2
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 6, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, otherKey, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				ingress := uint16(1) // from peering link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))

					// ... The SegID accumulator wasn't updated from HF[1],
					// it is still the same. That is the key behavior.
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{6, 3, 0},
						},
						NumINF:   2,
						NumLines: 9,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].HopField.Mac =
					computeMAC(t, otherKey, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)

				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))

					// The SegID should not get updated on arrival. If it is, then MAC validation
					// of HF1 will fail. Otherwise, this isn't visible because we changed segment.
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering consdir downstream": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 9, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, otherKey, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				ingress := uint16(1)
				egress := uint16(0)
				// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
				// so, already set for the before-processing state.
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))

					// ... The SegID accumulator should have been updated.
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering non consdir upstream": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{9, 3, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, otherKey, dpath.InfoFields[0], dpath.HopFields[2].HopField)

				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.HopLines))

					// After-processing, the SegID should have been updated
					// (on ingress) to be that of HF[1], which happens to be
					// the Segment's SegID. That is what we already have as
					// we only change it in the before-processing version
					// of the packet.
					egress = 1
				} else {
					// We're going against construction order, so the before-processing accumulator
					// value is that of the previous hop in traversal order. The story starts with
					// the packet arriving at hop 1, so the accumulator value must match hop field
					// 0, which derives from hop field[1]. HopField[0]'s MAC is not checked during
					// this test.
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit direct": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{1}, // Interface 3 is in the external interfaces of a sibling router
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 3}},
					{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
				}
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0) // To make sure it gets updated.
				if afterProcessing {
					egress = uint16(3) // The sibling router is locally mapped to the egress ifID.
					// The link is specific to the sibling. It has the address. So we don't expect:
					// dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					[]uint16{51},
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF: 0,
							CurrHF:  3,
							SegLen:  [3]uint8{6, 6, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 0}}, // Src,
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 51}}, // IA 110
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},  // IA 110
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},  // Dst
					},
				}
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)

				var dstAddr *net.UDPAddr
				ingress := uint16(51) // == consEgress, bc non-consdir
				egress := uint16(0)   // To check that it is updated
				if afterProcessing {
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					egress = uint16(3) // Internal hop => egress points at sibling router.
					// The link is specific to the sibling. It has the address. So we don't expect:
					// dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				}

				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"inbound flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				assert.NoError(t, spkt.SetDstAddr(dst))
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 16},
				}
				dpath.Base.PathMeta.SegLen[0] = 6 + 5 // 2 hops + 1 flyover
				dpath.Base.NumLines = 6 + 5
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[2].HopField)
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"outbound flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 16},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 16},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 16},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 5 * 3 // 3 flyovers
				dpath.NumLines = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)
				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[0].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"reservation expired": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						Flyover: true, ResStartTime: 5, Duration: 2, Bw: 16},
				}
				dpath.Base.PathMeta.SegLen[0] = 6 + 5 // 1 flyover
				dpath.NumLines = 11
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.Base.PathMeta)
				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[0].HopField)
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: discarded,
		},
		"brtransit flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
						Flyover: true, Bw: 5, ResStartTime: 123, Duration: 304},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}

				dpath.Base.PathMeta.SegLen[0] = 11 // 1 flyover
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				ingress := uint16(1)
				egress := uint16(2)
				if afterProcessing {
					dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[1].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit non consdir flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
						Flyover: true, ResID: 42, ResStartTime: 5, Duration: 301, Bw: 16},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				ingress := uint16(1)
				egress := uint16(2)
				if afterProcessing {
					dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[1].HopField)
					require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
				} else {
					// Against construction direction.
					dpath.InfoFields[0].UpdateSegID(
						computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField))
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit direct flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, // Interface 3 is in the external interfaces of a sibling router
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 3},
						Flyover: true, ResID: 42, ResStartTime: 5, Duration: 301, Bw: 16},
					{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
				}
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.PathMeta.CurrHF = 3
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(3)
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit xover flyover ingress": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{51},
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(3): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						NumINF:   2,
						NumLines: 9 + 5, // 1 flyover
						PathMeta: hummingbird.MetaHdr{
							CurrINF: 0,
							CurrHF:  3,
							SegLen:  [3]uint8{8, 6, 0}, // Flyover on first segment
							BaseTS:  util.TimeToSecs(now),
						},
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 0}}, // Src,
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 51},
							Flyover: true, Bw: 5, ResStartTime: 5, Duration: 310}, // IA 110
						// xover here.
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}}, // IA 110
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}}, // Dst
					},
				}
				dpath.HopFields[1].HopField.Mac = computeAggregateMacExplicitInEg(
					t, key, hbirdKey, spkt.DstIA, spkt.PayloadLen, 3, 51,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				var dstAddr *net.UDPAddr
				ingress := uint16(51) // == consEgress, bc non-consdir
				egress := uint16(0)   // To check that it is updated
				if afterProcessing {
					dpath.HopFields[1].Flyover = false
					dpath.HopFields[2].Flyover = true
					dpath.HopFields[2].Bw = 5
					dpath.HopFields[2].ResStartTime = 5
					dpath.HopFields[2].Duration = 310
					dpath.HopFields[1].HopField.Mac =
						computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					dpath.HopFields[2].HopField.Mac = computeAggregateMacExplicitInEg(t, key, hbirdKey,
						spkt.DstIA, spkt.PayloadLen, 3, 51,
						dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
					dpath.PathMeta.SegLen[0] -= 2
					dpath.PathMeta.SegLen[1] += 2
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					egress = uint16(3) // Internal hop => egress points at sibling router.
					// The link is specific to the sibling. It has the address. So we don't expect:
					// dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				} else {
					// The BR is going to update the segment ID based on the regular SCION MAC,
					// not the flyover one. Since both are XOR-aggregated into the mac field,
					// we need to de-aggregate the flyover first.
					dpath.InfoFields[0].UpdateSegID(deaggregateFlyoverFromMac(
						t,
						key,
						dpath.InfoFields[0],
						dpath.HopFields[1],
					))
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"astransit xover flyover egress": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{3},
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(51): netip.MustParseAddrPort("10.0.200.200:30043"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, dp *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						NumINF:   2,
						NumLines: 9 + 5, // 1 flyover
						PathMeta: hummingbird.MetaHdr{
							CurrINF: 1,
							CurrHF:  6,
							SegLen:  [3]uint8{6, 8, 0}, // Flyover on second segment
							BaseTS:  util.TimeToSecs(now),
						},
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 0}}, // Src,
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 51}}, // IA 110
						// xover here.
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}, // IA 110
							Flyover: true, Bw: 5, ResStartTime: 5, Duration: 310},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}}, // Dst
					},
				}
				dpath.HopFields[2].HopField.Mac = computeAggregateMacExplicitInEg(
					t, key, hbirdKey, spkt.DstIA, spkt.PayloadLen, 3, 51,
					dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				ingress := uint16(0) // from sibling router
				egress := uint16(3)
				if afterProcessing {
					// Restore flyover to xover ingress hop from the egress one.
					dpath.HopFields[2].Flyover = false
					dpath.HopFields[1].Flyover = true
					dpath.HopFields[1].Bw = 5
					dpath.HopFields[1].ResStartTime = 5
					dpath.HopFields[1].Duration = 310
					dpath.HopFields[2].HopField.Mac =
						computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
					dpath.PathMeta.SegLen[0] += 2
					dpath.PathMeta.SegLen[1] -= 2
					require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
				}
				pkt := router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
				// Replace the link of the packet with the one from dataplane.
				ifaces := router.ExtractInterfaces(dp)
				// At the xover egress border router, the packet enters the BR via 0, but the
				// sibling border router link is stored at the ingress on the AS (previous hop).
				pkt.Link = ifaces[51]
				return pkt
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering consdir flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 8, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 11,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Flyover: true, Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}
				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[1], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, hbirdKey, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				ingress := uint16(1) // from peering link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					// deaggregate MAC
					dpath.HopFields[1].HopField.Mac = computeMAC(
						t, key, dpath.InfoFields[1], dpath.HopFields[1].HopField)
					// ... The SegID accumulator wasn't updated from HF[1],
					// it is still the same. That is the key behavior.
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"brtransit peering non consdir flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{8, 3, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 11,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Flyover: true, Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}
				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].HopField.Mac = computeMAC(
					t, hbirdKey, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					// Deaggregate MAC.
					dpath.HopFields[1].HopField.Mac = computeMAC(
						t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					// The SegID should not get updated on arrival. If it is, then MAC validation
					// of HF1 will fail. Otherwise, this isn't visible because we changed segment.
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering consdir downstream flyovers": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{1, 11, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Flyover: true, Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}
				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, hbirdKey, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				ingress := uint16(1)
				egress := uint16(0)
				// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
				// so, already set for the before-processing state.
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					// Deaggregate MAC.
					dpath.HopFields[2].HopField.Mac = computeMAC(
						t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
					// ... The SegID accumulator should have been updated.
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
		"peering non consdir upstream flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{11, 3, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Flyover: true, Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}
				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, hbirdKey, dpath.InfoFields[0], dpath.HopFields[2].HopField)
				ingress := uint16(2) // from child link
				egress := uint16(0)
				if afterProcessing {
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					// Deaggregate MAC.
					dpath.HopFields[1].HopField.Mac = computeMAC(
						t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					// After-processing, the SegID should have been updated
					// (on ingress) to be that of HF[1], which happens to be
					// the Segment's SegID. That is what we already have as
					// we only change it in the before-processing version
					// of the packet.
					egress = 1
				} else {
					// We're going against construction order, so the before-processing accumulator
					// value is that of the previous hop in traversal order. The story starts with
					// the packet arriving at hop 1, so the accumulator value must match hop field
					// 0, which derives from hop field[1]. HopField[0]'s MAC is not checked during
					// this test.
					// Use de-aggregated MAC value for segID update
					scionMac := computeMAC(
						t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					dpath.InfoFields[0].UpdateSegID(scionMac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress)
			},
			assertFunc: notDiscarded,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			pkt, want := tc.mockMsg(false, dp), tc.mockMsg(true, dp)
			disp := dp.ProcessPkt(pkt)
			tc.assertFunc(t, disp)
			if disp == router.PDiscard {
				return
			}
			assertPktEqual(t, want, pkt)
		})
	}
}

// func TestHbirdPacketPath(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()
// 	key := []byte("testkey_xxxxxxxx")
// 	sv := []byte("test_secretvalue")
// 	now := time.Now()
// 	testCases := map[string]struct {
// 		mockMsg       func() *ipv4.Message
// 		prepareDPs    func(*gomock.Controller) []*router.DataPlane
// 		srcInterfaces []uint16
// 	}{
// 		"two hops consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("1-ff00:0:110"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{6, 0, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   1,
// 						NumLines: 6,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 						{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [2]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(01): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						01: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 01},
// 		},
// 		"two hops non consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:111"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{6, 0, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   1,
// 						NumLines: 6,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				//dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [2]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(01): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						01: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 40},
// 		},
// 		"six hops astransit xover consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{9, 9, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 18,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 31}},
// 						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
// 						{HopField: path.HopField{ConsIngress: 11, ConsEgress: 8}},
// 						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				dpath.InfoFields[1].SegID = 0x222
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [7]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[6] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
// 		},
// 		"six hops astransit xover non consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{9, 9, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 18,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 1}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
// 						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 8, ConsEgress: 11}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 3}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[5].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				// Reset SegID to original value
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [7]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[6] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
// 		},
// 		"six hops brtransit xover mixed consdir": {
// 			// up segment non consdir, down segment consdir
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{9, 9, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 18,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 1}},
// 						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 5}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
// 						{HopField: path.HopField{ConsIngress: 11, ConsEgress: 8}},
// 						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[1].SegID = 0x222
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [5]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8):  mock_router.NewMockBatchConn(ctrl),
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						11: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 11, 3},
// 		},
// 		"six hops three segs mixed consdir": {
// 			// two crossovers, first crossover is brtransit, second one is astransit
// 			// core segment is non consdir
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{6, 6, 6},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   3,
// 						NumLines: 18,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x333, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 8}},
// 						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[2].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				dpath.InfoFields[2].SegID = 0x333
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [5]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Child,
// 						5: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						31: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						31: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 31, 0, 3},
// 		},
// 		"three hops peering brtransit consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{3, 6},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 9,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
// 						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here as the second hop of a peering path
// 				// Uses the same segID as it's following hop
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [3]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Peer,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 5},
// 		},
// 		"three hops peering brtransit non consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{3, 6},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 9,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here as the second hop of a peering path
// 				// Uses the same segID as it's following hop
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [3]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Peer,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 5},
// 		},
// 		"four hops peering astransit consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{6, 6},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 12,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
// 						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 7}},
// 						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
// 						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				// No Segment update here
// 				// the second hop of a peering path uses the same segID as it's following hop
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				// reset segID
// 				dpath.InfoFields[0].SegID = 0x111
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [6]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
// 		},
// 		"four hops peering astransit non consdir": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{6, 6},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 12,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
// 						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 31}},
// 						{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here
// 				// the second hop of a peering path uses the same segID as it's following hop
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [6]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
// 		},
// 		"two hops consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("1-ff00:0:110"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{10, 0, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   1,
// 						NumLines: 10,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				// add flyover macs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 0,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [2]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(01): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						01: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 01},
// 		},
// 		"two hops non consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:111"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{10, 0, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   1,
// 						NumLines: 10,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				// aggregate macs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 1,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 40, 0,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [2]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(01): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						01: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 40},
// 		},
// 		"six hops astransit xover consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{15, 13, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 28,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 31},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 11, ConsEgress: 8},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				dpath.InfoFields[1].SegID = 0x222
// 				// aggregate flyover macs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
// 					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
// 					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [7]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[6] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
// 		},
// 		"six hops astransit xover non consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{15, 13, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 28,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 1},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 8, ConsEgress: 11},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 3},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[5].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				// aggregate with flyover macs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
// 					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
// 					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [7]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Core,
// 						11: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[6] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
// 		},
// 		"six hops brtransit xover mixed consdir flyovers": {
// 			// up segment non consdir, down segment consdir
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
// 					xtest.MustParseIA("3-ff00:0:333"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{15, 13, 0},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 28,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 1},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 11, ConsEgress: 8},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[1].SegID = 0x222
// 				//aggregate MACs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
// 					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
// 					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [5]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1):  mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						31: topology.Parent,
// 						1:  topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Child,
// 						7: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8):  mock_router.NewMockBatchConn(ctrl),
// 						uint16(11): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						11: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)
// 				return dps[:]
// 			}, // middle hop of second segment is astransit
// 			srcInterfaces: []uint16{0, 1, 5, 11, 3},
// 		},
// 		"six hops three segs mixed consdir flyovers": {
// 			// two crossovers, first crossover is brtransit, second one is astransit
// 			// core segment is non consdir
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{10, 8, 8},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   3,
// 						NumLines: 26,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x333, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 31},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 8}},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
// 					dpath.HopFields[4].HopField)
// 				dpath.InfoFields[2].UpdateSegID(dpath.HopFields[4].HopField.Mac)
// 				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
// 					dpath.HopFields[5].HopField)
// 				// Reset SegID to original value
// 				dpath.InfoFields[0].SegID = 0x111
// 				dpath.InfoFields[2].SegID = 0x333
// 				// aggregate flyover macs
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 5,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 8,
// 					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
// 					dpath.InfoFields[2], &dpath.HopFields[5], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [5]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Child,
// 						5: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						31: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(8): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						8:  topology.Child,
// 						31: topology.Core,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(3): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						3: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 31, 0, 3},
// 		},
// 		"three hops peering brtransit consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{5, 10},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 15,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here
// 				// The second hop of a peering path uses the same segID as it's following hop
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
// 					dpath.InfoFields[1], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [3]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Peer,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 5},
// 		},
// 		"three hops peering brtransit non consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{5, 10},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 15,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here
// 				// The second hop of a peering path uses the same segID as it's following hop
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
// 					dpath.InfoFields[1], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [3]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Peer,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 1, 5},
// 		},
// 		"four hops peering astransit consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{10, 10},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 20,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 7},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				// No Segment update here
// 				// The second hop of a peering path uses the same segID as it's following hop
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				// reset segID
// 				dpath.InfoFields[0].SegID = 0x111
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 7,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
// 					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [6]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
// 		},
// 		"four hops peering astransit non consdir flyovers": {
// 			mockMsg: func() *ipv4.Message {
// 				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
// 					xtest.MustParseIA("1-ff00:0:113"))
// 				dst := addr.MustParseHost("10.0.100.100")
// 				_ = spkt.SetDstAddr(dst)
// 				dpath := &hummingbird.Decoded{
// 					Base: hummingbird.Base{
// 						PathMeta: hummingbird.MetaHdr{
// 							CurrINF:   0,
// 							CurrHF:    0,
// 							SegLen:    [3]uint8{10, 10},
// 							BaseTS:    util.TimeToSecs(now),
// 							HighResTS: 500 << 22,
// 						},
// 						NumINF:   2,
// 						NumLines: 20,
// 					},
// 					InfoFields: []path.InfoField{
// 						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
// 					},
// 					HopFields: []hummingbird.FlyoverHopField{
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 7, ConsEgress: 31},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
// 							Bw: 5, ResStartTime: 123, Duration: 304},
// 					},
// 				}
// 				// Compute MACs and increase SegID while doing so
// 				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[1].HopField)
// 				// No Segment update here
// 				// The second hop of a peering path uses the same segID as it's following hop
// 				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
// 					dpath.HopFields[0].HopField)
// 				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[3].HopField)
// 				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
// 				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
// 					dpath.HopFields[2].HopField)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
// 					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 7,
// 					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
// 					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
// 				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
// 					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)
// 				ret := toMsg(t, spkt, dpath)
// 				return ret
// 			},
// 			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
// 				var dps [6]*router.DataPlane
// 				dps[0] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(40): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						40: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
// 				dps[1] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(31): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[2] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(7): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						7:  topology.Peer,
// 						31: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
// 				dps[3] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(1): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[4] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(2): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						1: topology.Peer,
// 						2: topology.Child,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					map[uint16]*net.UDPAddr{
// 						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
// 					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
// 				dps[5] = router.NewDP(
// 					map[uint16]router.BatchConn{
// 						uint16(5): mock_router.NewMockBatchConn(ctrl),
// 					},
// 					map[uint16]topology.LinkType{
// 						5: topology.Parent,
// 					},
// 					mock_router.NewMockBatchConn(ctrl),
// 					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
// 				return dps[:]
// 			},
// 			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
// 		},
// 	}
// 	for name, tc := range testCases {
// 		name, tc := name, tc
// 		t.Run(name, func(t *testing.T) {
// 			t.Parallel()
// 			dps := tc.prepareDPs(ctrl)
// 			input := tc.mockMsg()
// 			for i, dp := range dps {
// 				result, err := dp.ProcessPkt(tc.srcInterfaces[i], input)
// 				assert.NoError(t, err)
// 				input = &ipv4.Message{
// 					Buffers: [][]byte{result.OutPkt},
// 					Addr:    result.OutAddr,
// 					N:       len(result.OutPkt),
// 				}
// 			}
// 		})
// 	}
// }

// TODO(juagargi): write test for concurrent bandwidth check calls

// func TestBandwidthCheck(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	key := []byte("testkey_xxxxxxxx")
// 	sv := []byte("test_secretvalue")
// 	now := time.Now()

// 	dp := router.NewDP(
// 		map[uint16]router.BatchConn{
// 			uint16(2): mock_router.NewMockBatchConn(ctrl),
// 		},
// 		map[uint16]topology.LinkType{
// 			1: topology.Parent,
// 			2: topology.Child,
// 		},
// 		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

// 	spkt, dpath := prepHbirdMsg(now)
// 	dpath.HopFields = []hummingbird.FlyoverHopField{
// 		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 42,
// 			Bw: 2, ResStartTime: 123, Duration: 304},
// 		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
// 	}
// 	dpath.Base.PathMeta.SegLen[0] = 11
// 	dpath.Base.PathMeta.CurrHF = 3
// 	dpath.Base.NumLines = 11

// 	spkt.PayloadLen = 120
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

// 	msg := toLongMsg(t, spkt, dpath)

// 	_, err := dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)

// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.Error(t, err)

// 	time.Sleep(time.Duration(1) * time.Second)

// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)
// }

// func TestBandwidthCheckDifferentResID(t *testing.T) {
// 	// Verifies that packets of one reservation do not affect
// 	// available bandwidth of another reservation
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	key := []byte("testkey_xxxxxxxx")
// 	sv := []byte("test_secretvalue")
// 	now := time.Now()

// 	dp := router.NewDP(
// 		map[uint16]router.BatchConn{
// 			uint16(2): mock_router.NewMockBatchConn(ctrl),
// 		},
// 		map[uint16]topology.LinkType{
// 			1: topology.Parent,
// 			2: topology.Child,
// 		},
// 		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

// 	spkt, dpath := prepHbirdMsg(now)
// 	dpath.HopFields = []hummingbird.FlyoverHopField{
// 		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 24,
// 			Bw: 2, ResStartTime: 123, Duration: 304},
// 		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
// 	}
// 	dpath.Base.PathMeta.SegLen[0] = 11
// 	dpath.Base.PathMeta.CurrHF = 3
// 	dpath.Base.NumLines = 11

// 	spkt.PayloadLen = 120
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

// 	msg := toLongMsg(t, spkt, dpath)

// 	_, err := dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)

// 	dpath.HopFields[1].ResID = 32
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)

// 	dpath.HopFields[1].ResID = 42
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)
// }

// func TestBandwidthCheckDifferentEgress(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	key := []byte("testkey_xxxxxxxx")
// 	sv := []byte("test_secretvalue")
// 	now := time.Now()

// 	dp := router.NewDP(
// 		map[uint16]router.BatchConn{
// 			uint16(2): mock_router.NewMockBatchConn(ctrl),
// 			uint16(3): mock_router.NewMockBatchConn(ctrl),
// 		},
// 		map[uint16]topology.LinkType{
// 			1: topology.Parent,
// 			2: topology.Child,
// 			3: topology.Child,
// 		},
// 		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

// 	spkt, dpath := prepHbirdMsg(now)
// 	dpath.HopFields = []hummingbird.FlyoverHopField{
// 		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 42,
// 			Bw: 2, ResStartTime: 123, Duration: 304},
// 		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
// 	}
// 	dpath.Base.PathMeta.SegLen[0] = 11
// 	dpath.Base.PathMeta.CurrHF = 3
// 	dpath.Base.NumLines = 11

// 	spkt.PayloadLen = 120
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

// 	msg := toLongMsg(t, spkt, dpath)

// 	_, err := dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)

// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.Error(t, err)

// 	// Reservation with same resID but different Ingress/Egress pair is a different reservation
// 	dpath.HopFields[1].HopField.ConsEgress = 3
// 	spkt.PayloadLen = 120
// 	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
// 		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
// 	msg = toLongMsg(t, spkt, dpath)
// 	_, err = dp.ProcessPkt(1, msg)
// 	assert.NoError(t, err)
// }

// func toLongMsg(t *testing.T, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
// 	t.Helper()
// 	ret := &ipv4.Message{}
// 	spkt.Path = dpath
// 	buffer := gopacket.NewSerializeBuffer()
// 	payload := [120]byte{}
// 	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
// 		spkt, gopacket.Payload(payload[:]))
// 	require.NoError(t, err)
// 	raw := buffer.Bytes()
// 	ret.Buffers = make([][]byte, 1)
// 	ret.Buffers[0] = make([]byte, 1500)
// 	copy(ret.Buffers[0], raw)
// 	ret.N = len(raw)
// 	ret.Buffers[0] = ret.Buffers[0][:ret.N]
// 	return ret
// }

func prepHbirdMsg(now time.Time) (*slayers.SCION, *hummingbird.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        addr.MustParseIA("4-ff00:0:411"),
		SrcIA:        addr.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   26, // scionudpLayer + len("actualpayloadbytes")
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF:    3,
				SegLen:    [3]uint8{9, 0, 0},
				BaseTS:    util.TimeToSecs(now),
				HighResTS: 500 << 22,
			},
			NumINF:   1,
			NumLines: 9,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{},
	}
	return spkt, dpath
}

func prepHbirdSlayers(src, dst addr.IA) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        dst,
		SrcIA:        src,
		Path:         &hummingbird.Raw{},
		PayloadLen:   26, // scionudpLayer + len("actualpayloadbytes")
	}
	return spkt
}

func computeAggregateMac(
	t *testing.T,
	key []byte,
	sv []byte,
	dst addr.IA,
	l uint16,
	info path.InfoField,
	hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr,
) [path.MacLen]byte {
	return computeAggregateMacExplicitInEg(
		t, key, sv, dst, l, hf.HopField.ConsIngress, hf.HopField.ConsEgress,
		info, hf, meta)
}

func computeAggregateMacExplicitInEg(
	t *testing.T,
	key []byte,
	sv []byte,
	dst addr.IA,
	l uint16,
	hin uint16,
	heg uint16,
	info path.InfoField,
	hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr,
) [path.MacLen]byte {
	scionMac := computeMAC(t, key, info, hf.HopField)

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	ingress, egress := hin, heg
	if !info.ConsDir {
		// deleteme since reservations are not bidirectional,
		// specify here the exact ingress and egress that was used to make the reservation.
		ingress, egress = egress, ingress
	}

	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}

// deaggregateFlyoverFromMac removes the flyover from the SCION MAC.
func deaggregateFlyoverFromMac(
	t *testing.T,
	key []byte,
	info path.InfoField,
	flyover hummingbird.FlyoverHopField,
) [6]byte {
	scionMac := computeMAC(t, key, info, flyover.HopField) // Compute SCION MAC
	mac := flyover.HopField.Mac                            // Copy MAC.
	// MAC = S^F (SCION XOR Flyover).
	mac[0] = (mac[0] ^ scionMac[0]) ^ mac[0] // S^F ^ S = F ; F ^ S^F = S
	mac[1] = (mac[1] ^ scionMac[1]) ^ mac[1]

	return mac
}

// Computes flyovermac and aggregates it to existing mac in hopfield
func aggregateOntoScionMac(t *testing.T, sv []byte, dst addr.IA, l, hin, heg uint16,
	info path.InfoField, hf *hummingbird.FlyoverHopField, meta hummingbird.MetaHdr) {
	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	ingress, egress := hin, heg

	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i := range hf.HopField.Mac {
		hf.HopField.Mac[i] ^= flyoverMac[i]
	}
}
