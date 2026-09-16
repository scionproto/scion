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
	"bytes"
	"crypto/aes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	pr "github.com/scionproto/scion/router/priority"
)

// Hummingbird dataplane coverage. A check mark means that the behavior has a
// dedicated test for that packet mode; reservation checks apply only to
// flyovers by definition.
//
//	Behavior                              Best-effort  Flyover
//	Inbound delivery                      x            x
//	Inbound, converted reversed path      x            x
//	Outbound forwarding                   x            x
//	BR transit, construction direction    x            x
//	BR transit, reverse direction         x            x
//	Direct AS transit, ingress BR         x            x
//	Direct AS transit, egress BR          x            x
//	AS-transit cross-over, ingress BR     x            x
//	AS-transit cross-over, egress BR      x            x
//	Same-BR cross-over                    x            x
//	Peering boundary, construction dir.   x            x
//	Peering boundary, reverse dir.        x            x
//	After peering, downstream             x            x
//	Before peering, upstream              x            x
//	Malformed current-hop alignment       x            x
//	Invalid hop MAC / SCMP                x            x
//	Invalid source IA / SCMP              x            x
//	Invalid destination IA / SCMP         x            x
//	Invalid outbound source IA / SCMP     x            x
//	Invalid outbound destination IA/SCMP  x            x
//	Ingress router alert                  x            x
//	Egress router alert                   x            x
//	Expired reservation                   N/A          x
//	Stale/future packet freshness         N/A          x
//	Reservation exceeds bandwidth         N/A          x

// Notation for the test cases, re. packets that are not sourced or destined to the AS (transits):
// brtransit_*					No segment crossover	One BR owns ingress and egress
// brtransit_xover_*			Segment crossover		One BR owns ingress and egress
// astransit_direct_ingress_*	No crossover	First BR receives externally and forwards via AS
// astransit_direct_egress_*	No crossover	Second BR receives from AS, forwards externally
// astransit_xover_ingress_*	Segment crossover	First BR receives externally, forwards via AS
// astransit_xover_egress_*		Segment crossover	Second BR receives from AS, forwards externally
//
// Crossover detection is segment-type agnostic: it checks whether advancing
// changes CurrINF. The up->down fixtures therefore exercise the same dataplane
// branch as an up->core transition without duplicating the topology matrix.

// TestDataPlaneSetHbirdKey checks the lifecycle rules of DataPlane.SetHbirdKey: it must be set
// before the dataplane starts serving, rejects a nil key, and rejects being set twice.
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

// TestProcessHbirdPacket drives DataPlane.ProcessPkt with one crafted Hummingbird packet per
// forwarding scenario (see the coverage table above) and checks the packet is transformed
// exactly as an independently constructed "after processing" packet, or discarded, as declared
// by each case's assertFunc.
func TestProcessHbirdPacket(t *testing.T) {

	key := []byte("testkey_xxxxxxxx")
	otherKey := []byte("testkey_yyyyyyyy")
	hbirdKey := []byte("test_secretvalue")
	now := time.Now()

	// ProcessPacket assumes some pre-conditions:
	// * The ingress interface has to exist. This mock map is good for most test cases.
	//   Others need a custom one.
	// * InternalNextHops may not be nil. Empty is ok (sufficient unless testing AS transit).
	mockExternalInterfaces := []uint16{1, 2, 3}
	mockInternalNextHops := map[uint16]netip.AddrPort{}

	testCases := map[string]struct {
		prepareDP  func() *router.DataPlane
		mockMsg    func(*testing.T, bool, *router.DataPlane) *router.Packet
		assertFunc func(*testing.T, router.Disposition)
	}{
		"inbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"outbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := prepMalformedHbirdPath(now, true)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_consdir_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_non_consdir_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"malformed_current_hop_alignment_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := prepMalformedHbirdPath(now, true)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				assert.NoError(t, spkt.SetDstAddr(dst))
				ingress := uint16(1)
				egress := uint16(0)
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: discarded,
		},
		"malformed_current_hop_alignment_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces, nil, nil, mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, _ bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := prepMalformedHbirdPath(now, false)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				require.NoError(t, spkt.SetDstAddr(dst))
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 1, 0,
					pr.WithBestEffort)
			},
			assertFunc: discarded,
		},
		"brtransit_peering_consdir_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_peering_non_consdir_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet lands on the last (peering) hop of segment 0.
				// After processing, the packet is ready to be processed by
				// the first (peering) hop of segment 1.
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"peering_consdir_downstream_best-effort": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"peering_non_consdir_upstream_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"astransit_direct_ingress_best-effort": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				return directASTransitPkt(t, dp, now, key, hbirdKey, false, false, afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"astransit_direct_egress_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{3},
					map[uint16]topology.LinkType{1: topology.Core, 3: topology.Core},
					nil,
					map[uint16]netip.AddrPort{
						1: netip.MustParseAddrPort("10.0.200.200:30041"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				return directASTransitPkt(t, dp, now, key, hbirdKey, false, true, afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"astransit_xover_ingress_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
						2: topology.Child,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(2): netip.MustParseAddrPort("10.0.200.200:30042"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}}, // AS 111
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},  // AS 110 ingress BR
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},  // AS 110 egress BR
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}}, // AS 112
					},
				}
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)

				ingress := uint16(1) // == consEgress, bc non-consdir
				egress := uint16(0)  // To check that it is updated
				if afterProcessing {
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					egress = uint16(2) // Internal hop => egress points at sibling router.
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				}

				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_xover_best-effort": {
			// Cross-over (up->down shortcut) handled entirely on this BR: the
			// packet enters and leaves on external child links of the same BR.
			// Wire-level analogue: HummingbirdBestEffortChildToChildXover.
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Child,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF: 0,
							CurrHF:  3,
							SegLen:  [3]uint8{6, 6, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
					},
				}
				dpath.HopFields[1].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					// This BR owns both hop fields at the segment boundary. The first
					// increment crosses from its up-segment hop to its down-segment hop;
					// normal egress processing advances once more to the next AS.
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					egress = 2
				} else {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"inbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				assert.NoError(t, spkt.SetDstAddr(dst))
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
				}
				dpath.Base.PathMeta.SegLen[0] = 6 + 5 // 2 hops + 1 flyover
				dpath.Base.NumLines = 6 + 5
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[2].HopField)
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"inbound_reversed_scion_path_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces,
					nil,
					nil,
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				assert.NoError(t, spkt.SetDstAddr(dst))

				scionPath := prepReversedScionPathForInbound(t, now)
				dpath := &hummingbird.Decoded{}
				dpath.ConvertFromScionDecoded(scionPath)
				dpath.Base.PathMeta.BaseTS = util.TimeToSecs(now)
				dpath.Base.PathMeta.HighResTS = 500 << 22
				dpath.Base.PathMeta.SegLen[0] = 6 + 5
				dpath.Base.NumLines = 6 + 5
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2] = hummingbird.FlyoverHopField{
					HopField:     path.HopField{ConsIngress: 1, ConsEgress: 0},
					Flyover:      true,
					ResStartTime: 123,
					Duration:     304,
					Bw:           129,
				}
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				var dstAddr *net.UDPAddr
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[2].HopField)
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"inbound_reversed_scion_path_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					mockExternalInterfaces, nil, nil, mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				require.NoError(t, spkt.SetDstAddr(dst))

				scionPath := prepReversedScionPathForInbound(t, now)
				dpath := &hummingbird.Decoded{}
				dpath.ConvertFromScionDecoded(scionPath)
				dpath.PathMeta.BaseTS = util.TimeToSecs(now)
				dpath.PathMeta.HighResTS = 500 << 22
				dpath.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
				var dstAddr *net.UDPAddr
				if afterProcessing {
					dstAddr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: dstUDPPort}
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, 1, 0,
					pr.WithBestEffort)
			},
			assertFunc: notDiscarded,
		},
		"outbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 5 * 3 // 3 flyovers
				dpath.NumLines = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)
				ingress := uint16(0)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[0].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
					egress = 1
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"reservation_expired_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						Flyover: true, ResStartTime: 5, Duration: 2, Bw: 129},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 129},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 5 * 3 // 3 flyovers
				dpath.NumLines = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)
				ingress := uint16(0)
				egress := uint16(0)
				priority := pr.WithPriority
				if afterProcessing {
					dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[0].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
					egress = 1
					priority = pr.WithBestEffort
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					priority)
			},
			assertFunc: notDiscarded,
		},
		"freshness_stale_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				return freshnessFlyoverPkt(
					t, now.Add(-router.MaxFreshnessTolerance-time.Second), key, hbirdKey,
					afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"freshness_future_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				return freshnessFlyoverPkt(
					t, now.Add(router.MaxFreshnessTolerance+time.Second), key, hbirdKey,
					afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"reservation_exceeds_bandwidth_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
				// Bandwidth codepoint 0 is the smallest reservation, 10 kbps,
				// i.e. 1250 bytes per second, which one packet already exceeds.
				largePayload := bytes.Repeat([]byte{0xab}, 2000)
				spkt.PayloadLen = uint16(8 + len(largePayload)) // udp header + payload
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 0},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 0},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40},
						Flyover: true, ResStartTime: 123, Duration: 304, Bw: 0},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 5 * 3 // 3 flyovers
				dpath.NumLines = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)

				serializeLargePayload := func(spkt *slayers.SCION, dpath path.Path) []byte {
					spkt.Path = dpath
					buffer := gopacket.NewSerializeBuffer()
					scionudpLayer := &slayers.UDP{}
					scionudpLayer.SrcPort = uint16(srcUDPPort)
					scionudpLayer.DstPort = uint16(dstUDPPort)
					scionudpLayer.SetNetworkLayerForChecksum(spkt)
					err := gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true},
						spkt, scionudpLayer, gopacket.Payload(largePayload))
					require.NoError(t, err)
					return buffer.Bytes()
				}

				ingress := uint16(0)
				egress := uint16(0)
				priority := pr.WithPriority
				if afterProcessing {
					dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[0].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
					egress = 1
					priority = pr.WithBestEffort
				}
				return router.NewPacket(serializeLargePayload(spkt, dpath), nil, nil,
					ingress, egress, priority)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_consdir_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
						Flyover: true, Bw: 129, ResStartTime: 123, Duration: 304},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}

				dpath.Base.PathMeta.SegLen[0] = 11 // 1 flyover
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				ingress := uint16(1)
				egress := uint16(2)
				if afterProcessing {
					dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[1].HopField)
					assert.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					egress = 2
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_non_consdir_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
						Flyover: true, ResID: 42, ResStartTime: 5, Duration: 301, Bw: 129},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"astransit_direct_ingress_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				return directASTransitPkt(t, dp, now, key, hbirdKey, true, false, afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"astransit_direct_egress_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{3},
					map[uint16]topology.LinkType{1: topology.Core, 3: topology.Core},
					nil,
					map[uint16]netip.AddrPort{
						1: netip.MustParseAddrPort("10.0.200.200:30041"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				return directASTransitPkt(t, dp, now, key, hbirdKey, true, true, afterProcessing)
			},
			assertFunc: notDiscarded,
		},
		"astransit_xover_ingress_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1},
					map[uint16]topology.LinkType{
						1: topology.Child,
						2: topology.Child,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(2): netip.MustParseAddrPort("10.0.200.200:30042"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}}, // AS 111
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
							Flyover: true, Bw: 129, ResStartTime: 5, Duration: 310}, // IA 110
						// xover here.
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},  // IA 110
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}}, // AS 112
					},
				}
				dpath.HopFields[1].HopField.Mac = computeAggregateMacForInterfaces(
					t, key, hbirdKey, spkt, dpath, 1, 2,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				var dstAddr *net.UDPAddr
				ingress := uint16(1) // == consEgress, bc non-consdir
				egress := uint16(0)  // To check that it is updated
				if afterProcessing {
					dpath.HopFields[1].Flyover = false
					dpath.HopFields[2].Flyover = true
					dpath.HopFields[2].Bw = 129
					dpath.HopFields[2].ResStartTime = 5
					dpath.HopFields[2].Duration = 310
					dpath.HopFields[1].HopField.Mac =
						computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					dpath.HopFields[2].HopField.Mac = computeAggregateMacForInterfaces(t, key, hbirdKey,
						spkt, dpath, 1, 2,
						dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
					dpath.PathMeta.SegLen[0] -= 2
					dpath.PathMeta.SegLen[1] += 2
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					egress = uint16(2) // Internal hop => egress points at sibling router.
					// The link is specific to the sibling. It has the address. So we don't expect:
					// dstAddr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				} else {
					// The BR is going to update the segment ID based on the regular SCION MAC,
					// not the flyover one. Since both are XOR-aggregated into the mac field,
					// we need to de-aggregate the flyover first.
					dpath.InfoFields[0].UpdateSegID(computeMAC(
						t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField))
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, dstAddr, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"astransit_xover_egress_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{2},
					map[uint16]topology.LinkType{1: topology.Child, 2: topology.Child},
					nil,
					map[uint16]netip.AddrPort{
						1: netip.MustParseAddrPort("10.0.200.200:30041"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := prepASTransitXoverEgressPath(now, false)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				if afterProcessing {
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
				}
				pkt := router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 0, 2,
					pr.WithBestEffort)
				pkt.Link = router.ExtractInterfaces(dp)[1]
				return pkt
			},
			assertFunc: notDiscarded,
		},
		"astransit_xover_egress_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{2},
					map[uint16]topology.LinkType{
						1: topology.Child,
						2: topology.Child,
					},
					nil, // No special connOpener.
					map[uint16]netip.AddrPort{
						uint16(1): netip.MustParseAddrPort("10.0.200.200:30041"),
					}, addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, dp *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := prepASTransitXoverEgressPath(now, true)
				dpath.HopFields[2].HopField.Mac = computeAggregateMacForInterfaces(
					t, key, hbirdKey, spkt, dpath, 1, 2,
					dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				ingress := uint16(0) // from sibling router
				egress := uint16(2)
				if afterProcessing {
					// Restore flyover to xover ingress hop from the egress one.
					dpath.HopFields[2].Flyover = false
					dpath.HopFields[1].Flyover = true
					dpath.HopFields[1].Bw = 129
					dpath.HopFields[1].ResStartTime = 5
					dpath.HopFields[1].Duration = 310
					dpath.HopFields[2].HopField.Mac =
						computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
					dpath.PathMeta.SegLen[0] += 2
					dpath.PathMeta.SegLen[1] -= 2
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
				}
				pkt := router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
				// Replace the link of the packet with the one from dataplane.
				ifaces := router.ExtractInterfaces(dp)
				// At the xover egress border router, the packet enters the BR via 0, but the
				// sibling border router link is stored at the ingress on the AS (previous hop).
				pkt.Link = ifaces[1]
				return pkt
			},
			assertFunc: notDiscarded,
		},
		"brtransit_xover_flyover": {
			// Cross-over (up->down shortcut) handled entirely on this BR, with a
			// flyover on the up-segment cross-over hop. Exercises doHbirdXoverFlyover
			// in the external-egress branch. Wire-level analogue:
			// HummingbirdFlyoverChildToChildXover.
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Child,
						2: topology.Child,
					},
					nil, // No special connOpener.
					mockInternalNextHops,
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    3,
							SegLen:    [3]uint8{3 + 5, 6, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 3 + 5 + 6,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
							Flyover: true, ResID: 42, Bw: 129, ResStartTime: 5, Duration: 301},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
					},
				}
				// Reservation spans ingress 1 (incoming hop) and egress 2 (outgoing hop).
				scionMac1 := computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[1].HopField.Mac = computeAggregateMacForInterfaces(
					t, key, hbirdKey, spkt, dpath, 1, 2,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac =
					computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				ingress := uint16(1)
				egress := uint16(0)
				if afterProcessing {
					dpath.HopFields[1].HopField.Mac = scionMac1
					require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
					require.NoError(t, dpath.IncPath(hummingbird.HopLines))
					dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					egress = 2
				} else {
					dpath.InfoFields[0].UpdateSegID(scionMac1)
				}
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_peering_consdir_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
							Flyover: true, Bw: 129, ResStartTime: 123, Duration: 304},
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
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[1], dpath.HopFields[1], dpath.PathMeta)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"brtransit_peering_non_consdir_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
							Flyover: true, Bw: 129, ResStartTime: 123, Duration: 304},
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
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"peering_consdir_downstream_flyover": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 11, 0}, // 1x3, 2x3 + 1x5
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
							Flyover: true, Bw: 129, ResStartTime: 123, Duration: 304},
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
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
		"peering_non_consdir_upstream_flyover": {
			prepareDP: func() *router.DataPlane {
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
			mockMsg: func(t *testing.T, afterProcessing bool, _ *router.DataPlane) *router.Packet {
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
							Flyover: true, Bw: 129, ResStartTime: 123, Duration: 304},
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
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, hbirdKey, spkt, dpath,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
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
				return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, ingress, egress,
					pr.WithPriority)
			},
			assertFunc: notDiscarded,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP()
			pkt, want := tc.mockMsg(t, false, dp), tc.mockMsg(t, true, dp)
			disp := dp.ProcessPkt(pkt)
			tc.assertFunc(t, disp)
			if disp == router.PDiscard {
				return
			}
			assertPktEqual(t, want, pkt)
		})
	}
}

// TestHbirdTokenBucketReservationIdentityAndConcurrency checks that the per-reservation token
// bucket used by checkReservationBandwidth is keyed by reservation ID and ingress/egress
// interfaces (not bandwidth), and that concurrent packets for the same reservation are
// accounted for safely.
func TestHbirdTokenBucketReservationIdentityAndConcurrency(t *testing.T) {
	key := []byte("testkey_xxxxxxxx")
	hbirdKey := []byte("test_secretvalue")
	now := time.Now()

	newDP := func() *router.DataPlane {
		return router.NewDPWithHummingbirdKey(
			[]uint16{1, 2},
			map[uint16]topology.LinkType{1: topology.Child, 2: topology.Child},
			nil, map[uint16]netip.AddrPort{}, addr.MustParseIA("1-ff00:0:110"),
			nil, key, hbirdKey)
	}
	makePkt := func(t *testing.T, resID uint32, egress, bw uint16) *router.Packet {
		t.Helper()
		spkt, dpath := prepHbirdMsg(now)
		spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
		dpath.PathMeta.CurrHF = 0
		dpath.PathMeta.SegLen = [3]uint8{8, 0, 0}
		dpath.NumLines = 8
		dpath.HopFields = []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: egress}, Flyover: true,
				ResID: resID, Bw: bw, ResStartTime: 5, Duration: 301},
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
		}
		dpath.HopFields[0].HopField.Mac = computeAggregateMac(
			t, key, hbirdKey, spkt, dpath, dpath.InfoFields[0], dpath.HopFields[0], dpath.PathMeta)
		return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 0, 0, pr.WithPriority)
	}

	t.Run("reservation key includes ID and interfaces but not bandwidth", func(t *testing.T) {
		dp := newDP()
		for _, tc := range []struct {
			resID  uint32
			egress uint16
			bw     uint16
			want   int
		}{
			{resID: 42, egress: 1, bw: 129, want: 1},
			{resID: 43, egress: 1, bw: 129, want: 2},
			{resID: 42, egress: 2, bw: 129, want: 3},
			{resID: 42, egress: 1, bw: 130, want: 3},
		} {
			pkt := makePkt(t, tc.resID, tc.egress, tc.bw)
			assert.NotEqual(t, router.PDiscard, dp.ProcessPkt(pkt))
			assert.Equal(t, tc.want, router.HummingbirdTokenBucketCount(dp))
		}
	})

	t.Run("concurrent packets share one bucket", func(t *testing.T) {
		dp := newDP()
		const packetCount = 64
		packets := make([]*router.Packet, packetCount)
		for i := range packets {
			packets[i] = makePkt(t, 42, 1, 1023)
		}
		dispositions := make([]router.Disposition, packetCount)
		var wg sync.WaitGroup
		for i := range packets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dispositions[i] = dp.ProcessPkt(packets[i])
			}()
		}
		wg.Wait()
		for _, disposition := range dispositions {
			assert.NotEqual(t, router.PDiscard, disposition)
		}
		assert.Equal(t, 1, router.HummingbirdTokenBucketCount(dp))
	})
}

// TestProcessHbirdSCMP checks that invalid Hummingbird packets (bad MAC, invalid source or
// destination IA, both inbound and outbound, both best-effort and flyover) are diverted to the
// slow path with the expected SCMP type/code/pointer, and produce a correctly addressed
// ParameterProblem reply quoting the offending packet.
func TestProcessHbirdSCMP(t *testing.T) {

	key := []byte("testkey_xxxxxxxx")
	hbirdKey := []byte("test_secretvalue")
	now := time.Now()

	testCases := map[string]struct {
		prepareDP         func() *router.DataPlane
		mockPkt           func(*testing.T, *router.DataPlane) (*router.Packet, []byte)
		expectedSlowPath  router.SlowPathRequestView
		expectedLayerType gopacket.LayerType
		assertReply       func(*testing.T, gopacket.Packet, []byte)
	}{
		"invalid_mac_inbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3},
					nil,
					nil,
					map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_flyover.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, true, invalidHbirdInbound, invalidHbirdMAC)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType: int8(slayers.SCMPTypeParameterProblem),
				Code:   slayers.SCMPCodeInvalidHopFieldMAC,
				// Pointer to the current Hummingbird hop line in the malformed packet.
				Pointer: 80,
			},
			// The slow-path response should be an SCMP Parameter Problem reporting the
			// invalid hop/flyover MAC.
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
			assertReply: func(t *testing.T, packet gopacket.Packet, original []byte) {
				scionLayer := packet.Layer(slayers.LayerTypeSCION)
				require.NotNil(t, scionLayer)
				scionPkt := scionLayer.(*slayers.SCION)
				// The response must travel back on a Hummingbird path towards the
				// original source IA, with the local router IA as sender.
				assert.EqualValues(t, hummingbird.PathType, scionPkt.PathType)
				assert.Equal(t, addr.MustParseIA("2-ff00:0:222"), scionPkt.DstIA)
				assert.Equal(t, addr.MustParseIA("1-ff00:0:110"), scionPkt.SrcIA)

				scmpParam := packet.Layer(slayers.LayerTypeSCMPParameterProblem)
				require.NotNil(t, scmpParam)
				quote := scmpParam.LayerPayload()
				require.NotEmpty(t, quote)
				// SCMP errors must quote the offending packet payload verbatim, subject
				// only to SCMP truncation limits.
				assert.True(t, bytes.Equal(original[:len(quote)], quote))
			},
		},
		"invalid_mac_inbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3},
					nil,
					nil,
					map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_best-effort.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, false, invalidHbirdInbound, invalidHbirdMAC)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidHopFieldMAC,
				Pointer: 80,
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_source_ia_inbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3},
					nil,
					nil,
					map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_best-effort.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, false, invalidHbirdInbound,
					invalidHbirdSourceIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidSourceAddress,
				Pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_source_ia_inbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3}, nil, nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_flyover.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, true, invalidHbirdInbound,
					invalidHbirdSourceIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidSourceAddress,
				Pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_destination_ia_inbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3}, nil, nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_best-effort.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, false, invalidHbirdInbound,
					invalidHbirdDestinationIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidDestinationAddress,
				Pointer: uint16(slayers.CmnHdrLen),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_destination_ia_inbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2, 3}, nil, nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/inbound_flyover.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, true, invalidHbirdInbound,
					invalidHbirdDestinationIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidDestinationAddress,
				Pointer: uint16(slayers.CmnHdrLen),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_source_ia_outbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/outbound_best-effort.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, false, invalidHbirdOutbound,
					invalidHbirdSourceIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidSourceAddress,
				Pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_source_ia_outbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/outbound_flyover.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, true, invalidHbirdOutbound,
					invalidHbirdSourceIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidSourceAddress,
				Pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_destination_ia_outbound_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/outbound_best-effort.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, false, invalidHbirdOutbound,
					invalidHbirdDestinationIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidDestinationAddress,
				Pointer: uint16(slayers.CmnHdrLen),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
		"invalid_destination_ia_outbound_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1}, map[uint16]topology.LinkType{1: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) (*router.Packet, []byte) {
				// Derived from TestProcessHbirdPacket/outbound_flyover.
				return invalidHbirdPkt(
					t, dp, now, key, hbirdKey, true, invalidHbirdOutbound,
					invalidHbirdDestinationIA)
			},
			expectedSlowPath: router.SlowPathRequestView{
				SPType:  int8(slayers.SCMPTypeParameterProblem),
				Code:    slayers.SCMPCodeInvalidDestinationAddress,
				Pointer: uint16(slayers.CmnHdrLen),
			},
			expectedLayerType: slayers.LayerTypeSCMPParameterProblem,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dp := tc.prepareDP()
			pkt, original := tc.mockPkt(t, dp)

			disp := dp.ProcessPkt(pkt)
			assert.Equal(t, router.PSlowPath, disp)
			assert.Equal(t, tc.expectedSlowPath, router.ExtractSlowPathRequest(pkt))

			err := dp.ProcessSlowPath(pkt)
			require.NoError(t, err)

			packet := gopacket.NewPacket(pkt.RawPacket, slayers.LayerTypeSCION, gopacket.Default)
			scmpLayer := packet.Layer(slayers.LayerTypeSCMP)
			require.NotNil(t, scmpLayer)
			scmp := scmpLayer.(*slayers.SCMP)
			expectedTypeCode := slayers.CreateSCMPTypeCode(
				slayers.SCMPType(tc.expectedSlowPath.SPType), tc.expectedSlowPath.Code)
			assert.Equal(t, expectedTypeCode, scmp.TypeCode)
			assert.NotNil(t, packet.Layer(tc.expectedLayerType))

			if tc.assertReply != nil {
				tc.assertReply(t, packet, original)
			}
		})
	}
}

// TestProcessHbirdRouterAlert checks that a Hummingbird packet whose current hop
// field carries a router-alert flag is diverted to the slow path (for a traceroute
// reply) rather than forwarded on the fast path.
func TestProcessHbirdRouterAlert(t *testing.T) {

	key := []byte("testkey_xxxxxxxx")
	hbirdKey := []byte("test_secretvalue")
	now := time.Now()

	// slowPathRouterAlert{Ingress,Egress} are -1 and -2 respectively (see dataplane.go).
	const (
		spTypeRouterAlertIngress int8 = -1
		spTypeRouterAlertEgress  int8 = -2
	)

	testCases := map[string]struct {
		prepareDP      func() *router.DataPlane
		mockPkt        func(*testing.T, *router.DataPlane) *router.Packet
		expectedSPType int8
	}{
		"ingress_router_alert_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil,
					map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) *router.Packet {
				return routerAlertPkt(t, dp, now, key, hbirdKey, false, true)
			},
			expectedSPType: spTypeRouterAlertIngress,
		},
		"egress_router_alert_best-effort": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil,
					map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) *router.Packet {
				return routerAlertPkt(t, dp, now, key, hbirdKey, false, false)
			},
			expectedSPType: spTypeRouterAlertEgress,
		},
		"ingress_router_alert_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{1: topology.Parent, 2: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) *router.Packet {
				return routerAlertPkt(t, dp, now, key, hbirdKey, true, true)
			},
			expectedSPType: spTypeRouterAlertIngress,
		},
		"egress_router_alert_flyover": {
			prepareDP: func() *router.DataPlane {
				return router.NewDPWithHummingbirdKey(
					[]uint16{1, 2},
					map[uint16]topology.LinkType{1: topology.Parent, 2: topology.Child},
					nil, map[uint16]netip.AddrPort{},
					addr.MustParseIA("1-ff00:0:110"), nil, key, hbirdKey)
			},
			mockPkt: func(t *testing.T, dp *router.DataPlane) *router.Packet {
				return routerAlertPkt(t, dp, now, key, hbirdKey, true, false)
			},
			expectedSPType: spTypeRouterAlertEgress,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP()
			pkt := tc.mockPkt(t, dp)
			disp := dp.ProcessPkt(pkt)
			assert.Equal(t, router.PSlowPath, disp)
			assert.Equal(t, tc.expectedSPType, router.ExtractSlowPathRequest(pkt).SPType)
		})
	}
}

// prepHbirdMsg builds a minimal, otherwise-empty Hummingbird SCION header and decoded path
// (with a single info field and no hop fields) for callers to fill in with their own hop fields
// and path metadata.
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

// prepReversedScionPathForInbound builds a plain SCION path already reversed into construction
// direction, for the "inbound_reversed_scion_path_*" cases that check delivery of a packet
// converted from a SCION reply path into a Hummingbird one.
func prepReversedScionPathForInbound(t *testing.T, now time.Time) *scion.Decoded {
	t.Helper()

	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
		},
		HopFields: []path.HopField{
			{ConsIngress: 1, ConsEgress: 0},
			{ConsIngress: 31, ConsEgress: 30},
			{ConsIngress: 41, ConsEgress: 40},
		},
	}
	reversed, err := sp.Reverse()
	require.NoError(t, err)
	return reversed.(*scion.Decoded)
}

// prepMalformedHbirdPath builds a Hummingbird path whose CurrHF points into the middle of a
// hop (a three-line regular hop, or an eleven-line encoding with a five-line flyover hop when
// flyover is true), which the router must reject as a malformed path.
func prepMalformedHbirdPath(now time.Time, flyover bool) *hummingbird.Decoded {
	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF: 4, SegLen: [3]uint8{9, 0, 0}, BaseTS: util.TimeToSecs(now),
			},
			NumINF: 1, NumLines: 9,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},
		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
			{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
			{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
		},
	}
	if flyover {
		dpath.PathMeta.SegLen[0] = 11
		dpath.NumLines = 11
		dpath.HopFields[1].Flyover = true
		dpath.HopFields[1].Bw = 16
		dpath.HopFields[1].ResStartTime = 123
		dpath.HopFields[1].Duration = 304
	}
	return dpath
}

// prepASTransitXoverEgressPath builds a two-segment Hummingbird path positioned at the
// down-segment hop of an AS-transit segment crossover, as seen by the egress BR: the packet
// arrives internally from the sibling ingress BR and is about to leave externally. If flyover
// is true, the down-segment hop carries the flyover moved there by the ingress BR.
func prepASTransitXoverEgressPath(now time.Time, flyover bool) *hummingbird.Decoded {
	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrINF: 1, CurrHF: 6, SegLen: [3]uint8{6, 6, 0},
				BaseTS: util.TimeToSecs(now),
			},
			NumINF: 2, NumLines: 12,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},
		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
		},
	}
	if flyover {
		dpath.PathMeta.SegLen[1] += 2
		dpath.NumLines += 2
		dpath.HopFields[2].Flyover = true
		dpath.HopFields[2].Bw = 129
		dpath.HopFields[2].ResStartTime = 5
		dpath.HopFields[2].Duration = 310
	}
	return dpath
}

// freshnessFlyoverPkt builds a valid outbound flyover whose packet timestamp is
// supplied by the caller. The reservation remains valid; only the freshness
// check demotes the processed packet to best effort.
func freshnessFlyoverPkt(
	t *testing.T,
	packetTime time.Time,
	key []byte,
	hbirdKey []byte,
	afterProcessing bool,
) *router.Packet {
	t.Helper()
	spkt, dpath := prepHbirdMsg(packetTime)
	spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
	dpath.PathMeta.CurrHF = 0
	dpath.PathMeta.SegLen[0] = 8
	dpath.NumLines = 8
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}, Flyover: true,
			Bw: 129, ResStartTime: 123, Duration: 304},
		{HopField: path.HopField{ConsIngress: 41, ConsEgress: 0}},
	}
	dpath.HopFields[0].HopField.Mac = computeAggregateMac(
		t, key, hbirdKey, spkt, dpath, dpath.InfoFields[0], dpath.HopFields[0],
		dpath.PathMeta)
	priority := pr.WithPriority
	egress := uint16(0)
	if afterProcessing {
		dpath.HopFields[0].HopField.Mac =
			computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0].HopField)
		dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
		require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
		priority = pr.WithBestEffort
		egress = 1
	}
	return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 0, egress, priority)
}

// directASTransitPkt builds one half of split-BR AS transit without a segment
// crossover. The ingress BR authenticates the current hop and forwards it
// internally without advancing; the egress BR completes egress processing,
// advances the path, and sends it externally.
func directASTransitPkt(
	t *testing.T,
	dp *router.DataPlane,
	now time.Time,
	key []byte,
	hbirdKey []byte,
	flyover bool,
	egressBR bool,
	afterProcessing bool,
) *router.Packet {
	t.Helper()
	spkt, dpath := prepHbirdMsg(now)
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
		{HopField: path.HopField{ConsIngress: 1, ConsEgress: 3}},
		{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
	}
	dpath.PathMeta.CurrHF = 3
	priority := pr.WithBestEffort
	advance := hummingbird.HopLines
	if flyover {
		dpath.PathMeta.SegLen[0] = 11
		dpath.NumLines = 11
		dpath.HopFields[1].Flyover = true
		dpath.HopFields[1].ResID = 42
		dpath.HopFields[1].ResStartTime = 5
		dpath.HopFields[1].Duration = 301
		dpath.HopFields[1].Bw = 129
		dpath.HopFields[1].HopField.Mac = computeAggregateMac(
			t, key, hbirdKey, spkt, dpath, dpath.InfoFields[0], dpath.HopFields[1],
			dpath.PathMeta)
		priority = pr.WithPriority
		advance = hummingbird.FlyoverLines
	} else {
		dpath.HopFields[1].HopField.Mac =
			computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
	}

	if !egressBR {
		egress := uint16(0)
		if afterProcessing {
			egress = 3 // Interface 3 belongs to the sibling egress BR.
		}
		return router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 1, egress, priority)
	}

	if afterProcessing {
		if flyover {
			dpath.HopFields[1].HopField.Mac =
				computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
		}
		dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
		require.NoError(t, dpath.IncPath(advance))
	}
	pkt := router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 0, 3, priority)
	// Interface 1 is external on the sibling ingress BR and identifies the link
	// on which this AS received the packet before internal forwarding.
	pkt.Link = router.ExtractInterfaces(dp)[1]
	return pkt
}

// invalidHbirdPosition selects where in the path invalidHbirdPkt places the packet's current
// hop.
type invalidHbirdPosition uint8

const (
	invalidHbirdInbound invalidHbirdPosition = iota
	invalidHbirdOutbound
)

// invalidHbirdField selects which field invalidHbirdPkt corrupts.
type invalidHbirdField uint8

const (
	invalidHbirdMAC invalidHbirdField = iota
	invalidHbirdSourceIA
	invalidHbirdDestinationIA
)

// invalidHbirdPkt derives an invalid packet from the valid inbound or outbound
// cases in TestProcessHbirdPacket. It authenticates every field except the one
// selected by invalidField, making that field the packet's only failure cause.
func invalidHbirdPkt(
	t *testing.T,
	dp *router.DataPlane,
	now time.Time,
	key []byte,
	hbirdKey []byte,
	flyover bool,
	position invalidHbirdPosition,
	invalidField invalidHbirdField,
) (*router.Packet, []byte) {
	t.Helper()

	// Start with the endpoint IAs from the base packet. The position-specific
	// setup below makes the appropriate endpoint local and moves the packet to
	// either the first or final hop of the path.
	spkt, dpath := prepHbirdMsg(now)
	var current int
	var ingress uint16
	switch position {
	case invalidHbirdInbound:
		// Reproduce TestProcessHbirdPacket/inbound_{best-effort,flyover}: the
		// final hop enters the local AS through external interface 1.
		spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
		require.NoError(t, spkt.SetDstAddr(addr.MustParseHost("10.0.100.100")))
		dpath.HopFields = []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
			{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
			{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
		}
		current = 2
		dpath.PathMeta.CurrHF = 6
		ingress = 1
	case invalidHbirdOutbound:
		// Reproduce TestProcessHbirdPacket/outbound_{best-effort,flyover}: the
		// first hop enters the BR internally and leaves on interface 1.
		spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
		dpath.HopFields = []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},
			{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
			{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
		}
		current = 0
		dpath.PathMeta.CurrHF = 0
	default:
		require.FailNow(t, "unknown Hummingbird packet position", "position: %d", position)
	}

	// Invalidate the selected IA before computing the MAC because both IAs are
	// covered by a flyover aggregate MAC.
	switch invalidField {
	case invalidHbirdMAC:
	case invalidHbirdSourceIA:
		if position == invalidHbirdInbound {
			spkt.SrcIA = addr.MustParseIA("1-ff00:0:110")
		} else {
			spkt.SrcIA = addr.MustParseIA("2-ff00:0:222")
		}
	case invalidHbirdDestinationIA:
		if position == invalidHbirdInbound {
			spkt.DstIA = addr.MustParseIA("4-ff00:0:411")
		} else {
			spkt.DstIA = addr.MustParseIA("1-ff00:0:110")
		}
	default:
		require.FailNow(t, "unknown invalid Hummingbird field", "field: %d", invalidField)
	}

	// Authenticate the current hop according to the selected packet mode. For
	// IA failures this ensures that IA validation is the only failing check.
	priority := pr.WithBestEffort
	if flyover {
		dpath.PathMeta.SegLen[0] = 11
		dpath.NumLines = 11
		dpath.HopFields[current].Flyover = true
		dpath.HopFields[current].Bw = 129
		dpath.HopFields[current].ResStartTime = 123
		dpath.HopFields[current].Duration = 304
		dpath.HopFields[current].HopField.Mac = computeAggregateMac(
			t, key, hbirdKey, spkt, dpath, dpath.InfoFields[0], dpath.HopFields[current],
			dpath.PathMeta)
		priority = pr.WithPriority
	} else {
		dpath.HopFields[current].HopField.Mac =
			computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[current].HopField)
	}
	if invalidField == invalidHbirdMAC {
		dpath.HopFields[current].HopField.Mac[0] ^= 0xff
	}

	// Preserve the exact offending packet before handing the mutable copy to the
	// dataplane; ProcessSlowPath must quote these original bytes in its response.
	raw := toBytes(t, spkt, dpath)
	original := bytes.Clone(raw)
	pkt := router.NewPacket(raw, nil, nil, ingress, 0, priority)
	if ingress != 0 {
		pkt.Link = router.ExtractInterfaces(dp)[ingress]
	}
	return pkt, original
}

// routerAlertPkt builds a valid BR-transit Hummingbird packet with exactly one
// router-alert flag set on its current hop. The packet can use either a regular
// hop MAC or a flyover aggregate MAC.
func routerAlertPkt(
	t *testing.T,
	dp *router.DataPlane,
	now time.Time,
	key []byte,
	hbirdKey []byte,
	flyover bool,
	ingressAlert bool,
) *router.Packet {
	t.Helper()

	// Create the current transit hop and set exactly the requested alert bit.
	spkt, dpath := prepHbirdMsg(now)
	current := hummingbird.FlyoverHopField{
		HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
		Flyover:  flyover, Bw: 129, ResStartTime: 123, Duration: 304,
	}
	current.HopField.IngressRouterAlert = ingressAlert
	current.HopField.EgressRouterAlert = !ingressAlert

	// Place the alert-bearing hop between neighboring hops and make it current.
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
		current,
		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
	}
	dpath.PathMeta.CurrHF = 3

	// Compute the MAC only after setting the alert flag because router-alert bits
	// are authenticated. Flyovers additionally require the five-line encoding.
	priority := pr.WithBestEffort
	if flyover {
		dpath.PathMeta.SegLen[0] = 11
		dpath.NumLines = 11
		dpath.HopFields[1].HopField.Mac = computeAggregateMac(
			t, key, hbirdKey, spkt, dpath, dpath.InfoFields[0], dpath.HopFields[1],
			dpath.PathMeta)
		priority = pr.WithPriority
	} else {
		dpath.HopFields[1].HopField.Mac =
			computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
	}

	// Attach the configured external ingress link so ingress/egress alert logic
	// observes the same link scope as normal dataplane processing.
	pkt := router.NewPacket(toBytes(t, spkt, dpath), nil, nil, 1, 0, priority)
	pkt.Link = router.ExtractInterfaces(dp)[1]
	return pkt
}

// computeAggregateMac computes an aggregate MAC (SCION MAC XORed with flyover MAC) for hf,
// deriving the reservation's ingress/egress interfaces from hf's ConsIngress/ConsEgress and
// info's construction direction. Use computeAggregateMacForInterfaces directly when the
// reservation's interfaces differ from the hop field's (e.g. at a crossover).
func computeAggregateMac(
	t *testing.T,
	key []byte,
	sv []byte,
	spkt *slayers.SCION,
	dpath *hummingbird.Decoded,
	info path.InfoField,
	hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr,
) [path.MacLen]byte {
	ingress, egress := hf.HopField.ConsIngress, hf.HopField.ConsEgress
	if !info.ConsDir {
		ingress, egress = egress, ingress
	}
	return computeAggregateMacForInterfaces(
		t, key, sv, spkt, dpath, ingress, egress,
		info, hf, meta)
}

// computeAggregateMacForInterfaces computes an aggregate MAC using ingress and
// egress in packet traversal direction, independent of construction direction.
func computeAggregateMacForInterfaces(
	t *testing.T,
	key []byte,
	sv []byte,
	spkt *slayers.SCION,
	dpath *hummingbird.Decoded,
	ingress uint16,
	egress uint16,
	info path.InfoField,
	hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr,
) [path.MacLen]byte {
	scionMac := computeMAC(t, key, info, hf.HopField)

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, spkt.DstIA,
		packetLenFromRouterView(t, spkt, dpath),
		hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}

// packetLenFromRouterView returns the total packet length as the router computes it for the
// flyover MAC (via slayers.SCION.PacketLen), by round-tripping dpath through its raw encoding
// exactly as the router would see it on the wire.
func packetLenFromRouterView(
	t *testing.T,
	spkt *slayers.SCION,
	dpath *hummingbird.Decoded,
) uint16 {
	t.Helper()

	rawBytes := make([]byte, dpath.Len())
	require.NoError(t, dpath.SerializeTo(rawBytes))

	rawPath := &hummingbird.Raw{}
	require.NoError(t, rawPath.DecodeFromBytes(rawBytes))

	spkt.Path = rawPath
	spkt.PathType = rawPath.Type()
	return spkt.PacketLen()
}
