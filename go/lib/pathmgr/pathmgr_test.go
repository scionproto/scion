// Copyright 2017 ETH Zurich
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

package pathmgr

import (
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/sciond"
)

var (
	iaX = &addr.ISD_AS{I: 1, A: 11}
	iaY = &addr.ISD_AS{I: 1, A: 12}
	iaZ = &addr.ISD_AS{I: 2, A: 21}
)

var (
	// Test topo:
	// XY1: X#122 -> Y#212
	// XY2: X#121 -> Y#211
	// YZ: Y#231 -> Z#321
	// XZ: X#131 -> Z#311
	// XYZ: X#121 -> Y#211 -> Y#231 -> Z#321
	pathXY1 = sciond.PathReplyEntry{
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{
					RawIsdas: iaX.IAInt(),
					IfID:     121,
				},
				{
					RawIsdas: iaY.IAInt(),
					IfID:     211,
				},
			},
		},
	}
	pathXY2 = sciond.PathReplyEntry{
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{
					RawIsdas: iaX.IAInt(),
					IfID:     122,
				},
				{
					RawIsdas: iaY.IAInt(),
					IfID:     212,
				},
			},
		},
	}
	pathXZ = sciond.PathReplyEntry{
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{
					RawIsdas: iaX.IAInt(),
					IfID:     131,
				},
				{
					RawIsdas: iaZ.IAInt(),
					IfID:     311,
				},
			},
		},
	}
	pathYZ = sciond.PathReplyEntry{
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{
					RawIsdas: iaY.IAInt(),
					IfID:     231,
				},
				{
					RawIsdas: iaZ.IAInt(),
					IfID:     321,
				},
			},
		},
	}
	pathXYZ = sciond.PathReplyEntry{
		Path: sciond.FwdPathMeta{
			Interfaces: []sciond.PathInterface{
				{
					RawIsdas: iaX.IAInt(),
					IfID:     121,
				},
				{
					RawIsdas: iaY.IAInt(),
					IfID:     211,
				},
				{
					RawIsdas: iaY.IAInt(),
					IfID:     231,
				},
				{
					RawIsdas: iaZ.IAInt(),
					IfID:     321,
				},
			},
		},
	}
)

type mockSCIONDService struct {
	replies []*sciond.PathReply
}

func (m *mockSCIONDService) Connect() (sciond.Connector, error) {
	return &mockSCIONDConn{replies: m.replies}, nil
}

func (m *mockSCIONDService) ConnectTimeout(timeout time.Duration) (sciond.Connector, error) {
	return nil, nil
}

type mockSCIONDConn struct {
	index   int
	replies []*sciond.PathReply
}

func (m *mockSCIONDConn) Paths(dst, src *addr.ISD_AS, max uint16,
	f sciond.PathReqFlags) (*sciond.PathReply, error) {
	if m.index >= len(m.replies) {
		return buildSCIONDReply(), nil
	}
	entry := m.replies[m.index]
	m.index++
	return entry, nil
}

func (m *mockSCIONDConn) ASInfo(ia *addr.ISD_AS) (*sciond.ASInfoReply, error) {
	return nil, nil
}

func (m *mockSCIONDConn) IFInfo(ifs []uint64) (*sciond.IFInfoReply, error) {
	return nil, nil
}

func (m *mockSCIONDConn) SVCInfo(svcTypes []sciond.ServiceType) (*sciond.ServiceInfoReply, error) {
	return nil, nil
}

func (m *mockSCIONDConn) RevNotificationFromRaw(revInfo []byte) (*sciond.RevReply, error) {
	return nil, nil
}

func (m *mockSCIONDConn) RevNotification(revInfo *path_mgmt.RevInfo) (*sciond.RevReply, error) {
	return &sciond.RevReply{
		Result: sciond.RevValid,
	}, nil
}

func (m *mockSCIONDConn) Close() error {
	return nil
}

func (m *mockSCIONDConn) SetDeadline(t time.Time) error {
	return nil
}

func TestQuery(t *testing.T) {
	api := &mockSCIONDService{
		replies: []*sciond.PathReply{
			buildSCIONDReply(),
			buildSCIONDReply(pathXY1),
			buildSCIONDReply(pathXY1, pathXY2),
		},
	}
	Convey("Create path manager (path set max age = 1 second)", t, func() {
		timers := &Timers{
			NormalRefire: 5 * time.Second,
			ErrorRefire:  5 * time.Second,
			MaxAge:       time.Second,
		}
		pm, err := New(api, timers, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)
		Convey("Query, receive 0 paths", func() {
			aps := pm.Query(iaX, iaY)
			SoMsg("aps", aps, ShouldResemble, AppPathSet{})
			SoMsg("aps len", len(aps), ShouldEqual, 0)
			Convey("Query, we have 0 paths and SCIOND is asked again, receive 1 path", func() {
				aps := pm.Query(iaX, iaY)
				SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1))
				SoMsg("aps len", len(aps), ShouldEqual, 1)
				Convey("Query immediately, same path is read from cache", func() {
					aps := pm.Query(iaX, iaY)
					SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1))
					SoMsg("aps len", len(aps), ShouldEqual, 1)
				})
				Convey("Wait 2 seconds for paths to expire, then query and get new paths", func() {
					<-time.After(2 * time.Second)
					aps := pm.Query(iaX, iaY)
					SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1, pathXY2))
					SoMsg("aps len", len(aps), ShouldEqual, 2)
				})
			})
		})
	})
}

func TestQueryFilter(t *testing.T) {
	api := &mockSCIONDService{
		replies: []*sciond.PathReply{
			buildSCIONDReply(pathXY1, pathXY2),
		},
	}
	Convey("Create path manager", t, func() {
		pm, err := New(api, &Timers{}, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)
		Convey("Query with filter, only one path should remain", func() {
			pp, err := NewPathPredicate("0-0#211")
			SoMsg("err", err, ShouldBeNil)
			SoMsg("pp", pp, ShouldNotBeNil)
			aps := pm.QueryFilter(iaX, iaY, pp)
			SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1))
		})
	})
}

func TestRegister(t *testing.T) {
	// Watch a dst IA, refreshing paths every second. On the third request, the SCIOND mock
	// returns a new set of paths.
	api := &mockSCIONDService{
		replies: []*sciond.PathReply{
			buildSCIONDReply(),
			buildSCIONDReply(),
			buildSCIONDReply(pathYZ),
			buildSCIONDReply(pathYZ),
			buildSCIONDReply(pathYZ),
			buildSCIONDReply(pathYZ),
			buildSCIONDReply(pathYZ),
		},
	}
	Convey("Create path manager", t, func() {
		timers := &Timers{
			NormalRefire: time.Second,
			ErrorRefire:  time.Second,
			MaxAge:       time.Second,
		}
		pm, err := New(api, timers, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)
		Convey("Register for path, receive 0 responses", func() {
			sp, err := pm.Watch(iaY, iaZ)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("aps", sp.Load().APS, ShouldResemble, AppPathSet{})
			Convey("Wait 5 seconds, reloading APS should contain fresh paths", func() {
				<-time.After(4 * time.Second)
				SoMsg("aps", sp.Load().APS, ShouldResemble, buildAPS(pathYZ))
			})
		})
	})
}

func TestRegisterFilter(t *testing.T) {
	api := &mockSCIONDService{
		replies: []*sciond.PathReply{
			buildSCIONDReply(pathXY1, pathXY2),
		},
	}
	Convey("Create path manager", t, func() {
		timers := &Timers{
			NormalRefire: time.Second,
			ErrorRefire:  time.Second,
			MaxAge:       time.Second,
		}
		pm, err := New(api, timers, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)
		Convey("Register filter IFID 122", func() {
			// Create a predicate that matches Y
			pp, err := NewPathPredicate("0-0#122")
			SoMsg("pp", pp, ShouldNotBeNil)
			SoMsg("err", err, ShouldBeNil)
			sp, err := pm.WatchFilter(iaX, iaY, pp)
			SoMsg("err", err, ShouldBeNil)
			spd := sp.Load()
			SoMsg("aps", spd.APS, ShouldResemble, buildAPS(pathXY2))
			Convey("Wait 3 seconds, reloading the path filter no longer contains XY2", func() {
				// SCIOND no longer sends any paths; since we're watching iaX->iaY, the paths
				// will automatically disappear from sp
				<-time.After(3 * time.Second)
				spd := sp.Load()
				SoMsg("aps", spd.APS, ShouldResemble, AppPathSet{})
			})
		})
	})
}

func TestRevoke(t *testing.T) {
	api := &mockSCIONDService{
		replies: []*sciond.PathReply{
			buildSCIONDReply(pathXY1, pathXY2),
			buildSCIONDReply(pathXZ, pathXYZ),
		},
	}
	Convey("Create path manager", t, func() {
		timers := &Timers{
			NormalRefire: time.Minute,
			ErrorRefire:  time.Minute,
			MaxAge:       time.Minute,
		}
		pm, err := New(api, timers, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)
		Convey("Populate cache via Query, Watch, WatchFilter for different destinations", func() {
			// Needs 1 query to SCIOND, which retrieves pathXY1 and pathXY2
			aps := pm.Query(iaX, iaY)
			SoMsg("aps query", aps, ShouldResemble, buildAPS(pathXY1, pathXY2))
			// Needs 1 query to SCIOND, which retrieves pathX and pathZ
			sp, err := pm.Watch(iaX, iaZ)
			SoMsg("err register", err, ShouldBeNil)
			spd := sp.Load()
			SoMsg("aps register", spd.APS, ShouldResemble, buildAPS(pathXZ, pathXYZ))
			// Needs 0 queries to SCIOND (SyncPaths created for previous
			// query), and the filter keeps only pathXYZ
			pp, err := NewPathPredicate("0-0#231")
			SoMsg("err predicate", err, ShouldBeNil)
			spf, err := pm.WatchFilter(iaX, iaZ, pp)
			SoMsg("err register filter", err, ShouldBeNil)
			spd = spf.Load()
			SoMsg("aps register filter", spd.APS, ShouldResemble, buildAPS(pathXYZ))
			Convey("Revoke a path that's not part of any path set", func() {
				// Call revoke directly on the cache to avoid parsing a raw rev notification
				ia := &addr.ISD_AS{I: 5, A: 5}
				pm.cache.revoke(uifidFromValues(ia, 50))
				aps := pm.Query(iaX, iaY)
				SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1, pathXY2))
			})
			Convey("Revoke a path that's in Query, but not in Watch/WatchFilter path sets", func() {
				// This removes an UIFID from pathXY2
				pm.cache.revoke(uifidFromValues(iaY, 212))
				aps := pm.Query(iaX, iaY)
				SoMsg("aps", aps, ShouldResemble, buildAPS(pathXY1))
			})
			Convey("Revoke a path that's in Watch and WatchFilter, but not in Query", func() {
				pm.cache.revoke(uifidFromValues(iaY, 231))
				spd := sp.Load()
				// XYZ and XZ were in the path set, but now that XYZ's been
				// filtered out only XZ remains
				SoMsg("aps register", spd.APS, ShouldResemble, buildAPS(pathXZ))
				spd = spf.Load()
				// XYZ matched the filter, but now it's been revoked so nothing remains
				SoMsg("aps register filter", spd.APS, ShouldResemble, buildAPS())
			})
		})
	})
}

func buildAPS(replyPaths ...sciond.PathReplyEntry) AppPathSet {
	reply := &sciond.PathReply{
		ErrorCode: sciond.ErrorOk,
	}
	for _, p := range replyPaths {
		reply.Entries = append(reply.Entries, p)
	}
	return NewAppPathSet(reply)
}

func buildSCIONDReply(entries ...sciond.PathReplyEntry) *sciond.PathReply {
	errorCode := sciond.ErrorOk
	if entries == nil {
		errorCode = sciond.ErrorNoPaths
	}
	return &sciond.PathReply{
		ErrorCode: errorCode,
		Entries:   entries,
	}
}
