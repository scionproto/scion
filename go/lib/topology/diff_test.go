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

package topology

import (
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

func TestTopoDiffEmpty(t *testing.T) {
	Convey("Empty should report correctly", t, func() {
		t := &TopoDiff{}
		Convey("If TopoDiff is empty", func() {
			SoMsg("IgnoreTime set", t.Empty(true), ShouldBeTrue)
			SoMsg("IgnoreTime unset", t.Empty(false), ShouldBeTrue)
		})
		Convey("If TopoDiff is not empty", func() {
			Convey("Diff in time related fields", func() {
				t.TTL = 1
				SoMsg("IgnoreTime set", t.Empty(true), ShouldBeTrue)
				SoMsg("IgnoreTime unset", t.Empty(false), ShouldBeFalse)
			})
			Convey("Diff in time unrelated fields", func() {
				t.MTU = 1
				SoMsg("IgnoreTime set", t.Empty(true), ShouldBeFalse)
				SoMsg("IgnoreTime unset", t.Empty(false), ShouldBeFalse)
			})
		})
	})
}

func TestCompare(t *testing.T) {
	fn := "testdata/basic.json"
	load := func() *Topo {
		loadTopo(fn, t)
		return testTopo
	}
	c := load()
	Convey("Compare should report correctly", t, func() {
		o := load()
		Convey("If nothing is changed", func() {
			SoMsg("Empty", Compare(o, c).Empty(false), ShouldBeTrue)
		})
		Convey("If value fields are changed", func() {
			Convey("Timestamp", func() {
				o.Timestamp = time.Now()
				compareTopoDiff(Compare(o, c), &TopoDiff{Timestamp: DiffChanged})
			})
			Convey("TimestampHuman", func() {
				o.TimestampHuman = "α-Ω"
				compareTopoDiff(Compare(o, c), &TopoDiff{TimestampHuman: DiffChanged})
			})
			Convey("TTL", func() {
				o.TTL = 42
				compareTopoDiff(Compare(o, c), &TopoDiff{TTL: DiffChanged})
			})
			Convey("ISD_AS", func() {
				o.ISD_AS = addr.IA{}
				compareTopoDiff(Compare(o, c), &TopoDiff{ISD_AS: DiffChanged})
			})
			Convey("Overlay", func() {
				o.Overlay = overlay.Invalid
				compareTopoDiff(Compare(o, c), &TopoDiff{Overlay: DiffChanged})
			})
			Convey("MTU", func() {
				o.MTU = 42
				compareTopoDiff(Compare(o, c), &TopoDiff{MTU: DiffChanged})
			})
			Convey("Core", func() {
				o.Core = true
				compareTopoDiff(Compare(o, c), &TopoDiff{Core: DiffChanged})
			})
		})
		Convey("If service entries are changed", func() {
			o.BS["new"] = TopoAddr{}
			delete(o.BS, "bs1-ff00:0:311-1")
			o.BS["bs1-ff00:0:311-2"] = TopoAddr{}
			compareTopoDiff(Compare(o, c), &TopoDiff{
				BS: map[string]Diff{
					"new":              DiffAdded,
					"bs1-ff00:0:311-1": DiffRemoved,
					"bs1-ff00:0:311-2": DiffChanged,
				},
			})
		})
		Convey("If zookeeper entries are changed", func() {
			o.ZK[3] = &addr.AppAddr{
				L3: addr.SvcCS,
			}
			delete(o.ZK, 2)
			o.ZK[1] = &addr.AppAddr{
				L3: addr.SvcCS}
			compareTopoDiff(Compare(o, c), &TopoDiff{
				ZK: map[int]Diff{
					1: DiffChanged,
					2: DiffRemoved,
					3: DiffAdded,
				},
			})
		})
		Convey("If border router entries are changed", func() {
			Convey("An entry is added", func() {
				o.BR["new"] = BRInfo{
					IFIDs: []common.IFIDType{1337},
				}
				o.IFInfoMap[1337] = IFInfo{}
				compareTopoDiff(Compare(o, c), &TopoDiff{
					BR: map[string]BRDiff{
						"new": {
							Diff: DiffAdded,
						},
					},
					IFInfoMap: map[common.IFIDType]Diff{
						1337: DiffAdded,
					},
				})
			})
			Convey("An entry is removed", func() {
				delete(o.BR, "br1-ff00:0:311-1")
				delete(o.IFInfoMap, 1)
				delete(o.IFInfoMap, 3)
				delete(o.IFInfoMap, 8)
				compareTopoDiff(Compare(o, c), &TopoDiff{
					BR: map[string]BRDiff{
						"br1-ff00:0:311-1": {
							Diff: DiffRemoved,
						},
					},
					IFInfoMap: map[common.IFIDType]Diff{
						1: DiffRemoved,
						3: DiffRemoved,
						8: DiffRemoved,
					},
				})
			})
			Convey("An entry is modified", func() {
				info := o.BR["br1-ff00:0:311-1"]
				// modify BR entry
				removed := info.IFIDs[0]
				info.IFIDs = append(info.IFIDs[1:], 1337)
				info.CtrlAddrs.Overlay = overlay.IPv4
				info.InternalAddrs.Overlay = overlay.IPv4
				o.BR["br1-ff00:0:311-1"] = info
				// modify interface info
				changed := info.IFIDs[0]
				cinfo := o.IFInfoMap[changed]
				cinfo.MTU++
				o.IFInfoMap[changed] = cinfo
				compareTopoDiff(Compare(o, c), &TopoDiff{
					BR: map[string]BRDiff{
						"br1-ff00:0:311-1": {
							Diff:          DiffChanged,
							CtrlAddrs:     DiffChanged,
							InternalAddrs: DiffChanged,
							IFIDs: map[common.IFIDType]Diff{
								1337:    DiffAdded,
								changed: DiffChanged,
								removed: DiffRemoved,
							},
						},
					},
					IFInfoMap: map[common.IFIDType]Diff{
						changed: DiffChanged,
					},
				})
			})
		})
	})
}

func compareTopoDiff(a, b *TopoDiff) {
	SoMsg("Timestamp", a.Timestamp, ShouldEqual, b.Timestamp)
	SoMsg("TimestampHuman", a.TimestampHuman, ShouldEqual, b.TimestampHuman)
	SoMsg("TTL", a.TTL, ShouldEqual, b.TTL)
	SoMsg("ISD_AS", a.ISD_AS, ShouldEqual, b.ISD_AS)
	SoMsg("Overlay", a.Overlay, ShouldEqual, b.Overlay)
	SoMsg("MTU", a.MTU, ShouldEqual, b.MTU)
	SoMsg("Core", a.Core, ShouldEqual, b.Core)

	// Compare border routers
	compareIFIDS := func(key string, a, b map[common.IFIDType]Diff) {
		SoMsg(fmt.Sprintf("%s: Len", key), len(a), ShouldEqual, len(b))
		for k, v := range a {
			vb, ok := b[k]
			SoMsg(fmt.Sprintf("%s: %s ok", key, k), ok, ShouldBeTrue)
			SoMsg(fmt.Sprintf("%s: %s diff", key, k), vb, ShouldEqual, v)
		}
	}
	_ = compareIFIDS
	SoMsg(fmt.Sprintf("BR Len"), len(a.BR), ShouldEqual, len(b.BR))
	for k, v := range b.BR {
		vb, ok := a.BR[k]
		SoMsg(fmt.Sprintf("BR %s ok", k), ok, ShouldBeTrue)
		SoMsg(fmt.Sprintf("BR %s diff", k), vb, ShouldResemble, v)
	}

	// Compare IFInfoMap
	SoMsg("IFInfoMap Len", len(a.IFInfoMap), ShouldEqual, len(b.IFInfoMap))
	for k, v := range b.IFInfoMap {
		vb, ok := a.IFInfoMap[k]
		SoMsg(fmt.Sprintf("Zookeeper %s ok", k), ok, ShouldBeTrue)
		SoMsg(fmt.Sprintf("Zookeeper %s diff", k), vb, ShouldEqual, v)
	}
	// Compare services
	compareSvc := func(key string, a, b map[string]Diff) {
		SoMsg(fmt.Sprintf("%s: Len", key), len(a), ShouldEqual, len(b))
		for k, v := range b {
			vb, ok := a[k]
			SoMsg(fmt.Sprintf("%s: %s ok", key, k), ok, ShouldBeTrue)
			SoMsg(fmt.Sprintf("%s: %s diff", key, k), vb, ShouldEqual, v)
		}
	}
	compareSvc("BS", a.BS, b.BS)
	compareSvc("CS", a.CS, b.CS)
	compareSvc("PS", a.PS, b.PS)
	compareSvc("SB", a.SB, b.SB)
	compareSvc("RS", a.RS, b.RS)
	compareSvc("DS", a.DS, b.DS)
	compareSvc("SIG", a.SIG, b.SIG)
	// Compare zookeeper
	SoMsg("Zookeeper Len", len(a.ZK), ShouldEqual, len(b.ZK))
	for k, v := range b.ZK {
		vb, ok := a.ZK[k]
		SoMsg(fmt.Sprintf("Zookeeper %d ok", k), ok, ShouldBeTrue)
		SoMsg(fmt.Sprintf("Zookeeper %d diff", k), vb, ShouldEqual, v)
	}
}
