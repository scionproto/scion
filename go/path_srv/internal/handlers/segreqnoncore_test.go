// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	pathdbbe "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

var (
	g       = graph.NewDefaultGraph()
	timeout = 100 * time.Millisecond

	core1_110 = xtest.MustParseIA("1-ff00:0:110")
	core1_130 = xtest.MustParseIA("1-ff00:0:130")
	core1_120 = xtest.MustParseIA("1-ff00:0:120")
	as1_132   = xtest.MustParseIA("1-ff00:0:132")

	core2_210 = xtest.MustParseIA("2-ff00:0:210")
	as2_211   = xtest.MustParseIA("2-ff00:0:211")
	core2_220 = xtest.MustParseIA("2-ff00:0:220")
	as2_221   = xtest.MustParseIA("2-ff00:0:221")
	as2_222   = xtest.MustParseIA("2-ff00:0:222")

	seg130_132 = g.Beacon([]common.IFIDType{1316, 1619})
	seg110_130 = g.Beacon([]common.IFIDType{1113})
	seg120_210 = g.Beacon([]common.IFIDType{1222, 2221})
	seg120_220 = g.Beacon([]common.IFIDType{1222})

	seg210_211 = g.Beacon([]common.IFIDType{2123})
	seg210_220 = g.Beacon([]common.IFIDType{2122})
	seg210_222 = g.Beacon([]common.IFIDType{2123, 2326})

	seg220_130 = g.Beacon([]common.IFIDType{2212, 1213})
	seg220_210 = g.Beacon([]common.IFIDType{2221})
	seg220_221 = g.Beacon([]common.IFIDType{2224})
	seg220_222 = g.Beacon([]common.IFIDType{2224, 2426})

	topoFiles = map[addr.IA]string{
		as1_132: "topology_as1_132.json",
		as2_211: "topology_as2_211.json",
		as2_222: "topology_as2_222.json",
	}
)

type testCase struct {
	Name     string
	SrcIA    addr.IA
	DstIA    addr.IA
	Ups      []*seg.PathSegment
	Cores    []*seg.PathSegment
	Downs    []*seg.PathSegment
	Expected []*seg.Meta
}

func setupDB(t *testing.T, tc testCase) pathdb.PathDB {
	db, err := pathdbbe.New(":memory:")
	xtest.FailOnErr(t, err)
	insertSegs(t, db, tc.Ups, proto.PathSegType_up)
	insertSegs(t, db, tc.Cores, proto.PathSegType_core)
	insertSegs(t, db, tc.Downs, proto.PathSegType_down)
	return db
}

func insertSegs(t *testing.T, pathDB pathdb.PathDB, segs []*seg.PathSegment, st proto.PathSegType) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	for _, s := range segs {
		err := s.Validate()
		xtest.FailOnErr(t, err)
		_, err = pathDB.Insert(ctx, s, []proto.PathSegType{st})
		xtest.FailOnErr(t, err)
	}
}

func expectedSegs(ups, cores, downs []*seg.PathSegment) []*seg.Meta {
	e := make([]*seg.Meta, 0, len(ups)+len(cores)+len(downs))
	for _, u := range ups {
		e = append(e, seg.NewMeta(u, proto.PathSegType_up))
	}
	for _, c := range cores {
		e = append(e, seg.NewMeta(c, proto.PathSegType_core))
	}
	for _, d := range downs {
		e = append(e, seg.NewMeta(d, proto.PathSegType_down))
	}
	return e
}

func loadTopo(t *testing.T, ia addr.IA) *topology.Topo {
	fileName, ok := topoFiles[ia]
	if !ok {
		t.Fatalf("Missing %v in topoFile maps", ia)
	}
	topo, err := topology.LoadFromFile(filepath.Join("testdata", fileName))
	xtest.FailOnErr(t, err)
	return topo
}

type mockTS struct {
	trcs map[addr.ISD]*trc.TRC
}

var _ infra.TrustStore = (*mockTS)(nil)

func (t *mockTS) GetValidChain(ctx context.Context,
	ia addr.IA, source net.Addr) (*cert.Chain, error) {

	panic("not impl.")
}
func (t *mockTS) GetValidTRC(ctx context.Context,
	isd addr.ISD, source net.Addr) (*trc.TRC, error) {

	panic("not impl.")
}
func (t *mockTS) GetValidCachedTRC(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	panic("not impl.")
}
func (t *mockTS) GetChain(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error) {
	panic("not impl.")
}
func (t *mockTS) GetTRC(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error) {
	return t.trcs[isd], nil
}
func (t *mockTS) NewTRCReqHandler(recurseAllowed bool) infra.Handler {
	panic("not impl.")
}
func (t *mockTS) NewChainReqHandler(recurseAllowed bool) infra.Handler {
	panic("not impl.")
}
func (t *mockTS) SetMessenger(msger infra.Messenger) {
	panic("not impl.")
}

func defaultTS() *mockTS {
	return &mockTS{
		trcs: map[addr.ISD]*trc.TRC{
			1: {
				CoreASes: trc.CoreASMap{
					core1_110: nil,
					core1_120: nil,
					core1_130: nil,
				},
			},
			2: {
				CoreASes: trc.CoreASMap{
					core2_210: nil,
					core2_220: nil,
				},
			},
		},
	}
}

func TestSegReqLocal(t *testing.T) {
	log.SetupLogConsole("debug")
	testCases := []testCase{
		{
			Name:  "CoreDST: Single up, dst: core local",
			SrcIA: as1_132,
			DstIA: core1_110,
			Ups:   []*seg.PathSegment{seg130_132},
			Cores: []*seg.PathSegment{seg110_130},
			Expected: expectedSegs([]*seg.PathSegment{seg130_132},
				[]*seg.PathSegment{seg110_130}, nil),
		},
		{
			Name:  "CoreDST: Single up, dst: core remote",
			SrcIA: as1_132,
			DstIA: core2_220,
			Ups:   []*seg.PathSegment{seg130_132},
			Cores: []*seg.PathSegment{seg110_130, seg220_130},
			Expected: expectedSegs([]*seg.PathSegment{seg130_132},
				[]*seg.PathSegment{seg220_130}, nil),
		},
		{
			Name:     "CoreDST: No Up, single core, local",
			SrcIA:    as1_132,
			DstIA:    core1_110,
			Cores:    []*seg.PathSegment{seg110_130},
			Expected: nil,
		},
		{
			Name:  "CoreDST: Multi up, single core",
			SrcIA: as2_222,
			DstIA: core1_120,
			Ups:   []*seg.PathSegment{seg210_222, seg220_222},
			Cores: []*seg.PathSegment{seg120_220},
			Expected: expectedSegs([]*seg.PathSegment{seg220_222},
				[]*seg.PathSegment{seg120_220}, nil),
		},
		{
			Name:  "CoreDST: Multi up multi core",
			SrcIA: as2_222,
			DstIA: core1_120,
			Ups:   []*seg.PathSegment{seg210_222, seg220_222},
			Cores: []*seg.PathSegment{seg120_220, seg120_210},
			Expected: expectedSegs([]*seg.PathSegment{seg210_222, seg220_222},
				[]*seg.PathSegment{seg120_210, seg120_220}, nil),
		},
		{
			Name:     "NonCoreDST: Single up, no core, single down",
			SrcIA:    as2_222,
			DstIA:    as2_211,
			Ups:      []*seg.PathSegment{seg220_222},
			Downs:    []*seg.PathSegment{seg210_211},
			Expected: []*seg.Meta{},
		},
		{
			Name:  "NonCoreDst: Single up, core, down",
			SrcIA: as2_222,
			DstIA: as2_211,
			Ups:   []*seg.PathSegment{seg220_222},
			Cores: []*seg.PathSegment{seg210_220},
			Downs: []*seg.PathSegment{seg210_211},
			Expected: expectedSegs([]*seg.PathSegment{seg220_222},
				[]*seg.PathSegment{seg210_220}, []*seg.PathSegment{seg210_211}),
		},
		{
			Name:  "NonCoreDst: On up path dst",
			SrcIA: as2_222,
			DstIA: as2_221,
			Ups:   []*seg.PathSegment{seg220_222},
			Downs: []*seg.PathSegment{seg220_221},
			Expected: expectedSegs([]*seg.PathSegment{seg220_222}, nil,
				[]*seg.PathSegment{seg220_221}),
		},
		{
			Name:  "NonCoreDst: Path with shortcut",
			SrcIA: as2_222,
			DstIA: as2_211,
			Ups:   []*seg.PathSegment{seg220_222},
			Cores: []*seg.PathSegment{seg210_220},
			Downs: []*seg.PathSegment{seg210_211},
			Expected: expectedSegs([]*seg.PathSegment{seg220_222}, []*seg.PathSegment{seg210_220},
				[]*seg.PathSegment{seg210_211}),
		},
		{
			Name:  "NonCoreDst: Path through same core and different",
			SrcIA: as2_211,
			DstIA: as2_222,
			Ups:   []*seg.PathSegment{seg210_211},
			Cores: []*seg.PathSegment{seg220_210},
			Downs: []*seg.PathSegment{seg210_222, seg220_222},
			Expected: expectedSegs([]*seg.PathSegment{seg210_211}, []*seg.PathSegment{seg220_210},
				[]*seg.PathSegment{seg210_222, seg220_222}),
		},
		// TODO(lukedirtwalker): add tests with revocations.
		// TODO(lukedirtwalker): add tests with expired segs.
		// TODO(lukedirtwalker): add test with too many segments to test pruning.
	}
	Convey("SegReqLocal", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				db := setupDB(t, tc)
				segReq := &path_mgmt.SegReq{
					RawSrcIA: tc.SrcIA.IAInt(),
					RawDstIA: tc.DstIA.IAInt(),
					Flags: path_mgmt.SegReqFlags{
						CacheOnly: true,
					},
				}
				msger := &messenger.MockMessenger{}
				req := infra.NewRequest(
					infra.NewContextWithMessenger(context.Background(), msger),
					segReq,
					nil,
					&snet.Addr{IA: addr.IA{}},
					scrypto.RandUint64(),
					log.New(),
				)
				h := &segReqNonCoreHandler{
					segReqHandler: segReqHandler{
						baseHandler: &baseHandler{
							request:    req,
							pathDB:     db,
							revCache:   memrevcache.New(time.Minute, time.Minute),
							trustStore: defaultTS(),
							topology:   loadTopo(t, tc.SrcIA),
							logger:     req.Logger,
						},
						localIA: tc.SrcIA,
					},
				}
				h.Handle()
				SoMsg("Amount of sent replies", len(msger.SentSegReplies), ShouldEqual, 1)
				reply := msger.SentSegReplies[0]
				SoMsg("Reply ID should match request", reply.ID, ShouldEqual, req.ID)
				SoMsg("Reply should mirror req", reply.Msg.Req, ShouldEqual, segReq)
				if tc.Expected == nil {
					SoMsg("Not empty", reply.Msg.Recs, ShouldBeNil)
				} else {
					SoMsg("Empty reply", reply.Msg.Recs, ShouldNotBeNil)
					SoMsg("Segs", len(reply.Msg.Recs.Recs), ShouldEqual, len(tc.Expected))
					for i, s := range tc.Expected {
						SoMsg("RecType", reply.Msg.Recs.Recs[i].Type, ShouldEqual, s.Type)
						SoMsg("RecSeg", reply.Msg.Recs.Recs[i].Segment, ShouldResemble, s.Segment)
					}
				}
			})
		}
	})
}
