// Copyright 2017 Audrius Meskauskas with all possible permissions granted
// to ETH Zurich and Anapaya Systems
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

// Test hook functions as much as possible. Some hook functions do not define the returned
// value alone and are not testable this way.
package rpkt

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// Track if the hook is only queued once
var fetched = 0
var err error

func setupRtrPktHookTest() *RtrPkt {
	rpkt := NewRtrPkt()
	rpkt.Id = "id"
	fetched = 0

	return rpkt
}

func Test_Hooks_SrcDst_IA(t *testing.T) {
	rpkt := setupRtrPktHookTest()

	srcIA := &addr.ISD_AS{I: 1, A: 2}
	dstIA := &addr.ISD_AS{I: 3, A: 4}

	rpkt.hooks = hooks{
		SrcIA: []hookIA{func() (HookResult, *addr.ISD_AS, error) {
			fetched++
			return HookFinish, srcIA, nil
		}},

		DstIA: []hookIA{func() (HookResult, *addr.ISD_AS, error) {
			fetched++
			return HookFinish, dstIA, nil
		}},
	}

	Convey("Fetch SrcIA, DstIA via hook functions", t, func() {
		var ia *addr.ISD_AS

		ia, err = rpkt.DstIA()
		So(ia, ShouldEqual, dstIA)
		So(err, ShouldBeNil)

		ia, err = rpkt.DstIA()
		So(ia, ShouldEqual, dstIA)
		So(fetched, ShouldEqual, 1)
		So(err, ShouldBeNil)

		ia, err = rpkt.SrcIA()
		So(ia, ShouldEqual, srcIA)
		So(err, ShouldBeNil)

		ia, err = rpkt.SrcIA()
		So(ia, ShouldEqual, srcIA)
		So(fetched, ShouldEqual, 2)
		So(err, ShouldBeNil)
	})
}

func Test_Hooks_SrcDst_Host(t *testing.T) {
	rpkt := setupRtrPktHookTest()

	srcHost := addr.HostFromIP(net.IPv4(192, 168, 1, 37))
	dstHost := addr.HostFromIP(net.IPv4(192, 168, 1, 38))

	rpkt.hooks = hooks{
		SrcHost: []hookHost{func() (HookResult, addr.HostAddr, error) {
			fetched++
			return HookFinish, srcHost, nil
		}},

		DstHost: []hookHost{func() (HookResult, addr.HostAddr, error) {
			fetched++
			return HookFinish, dstHost, nil
		}},
	}

	Convey("Fetch SrcHost, DstHost via hook functions", t, func() {
		var host addr.HostAddr

		host, err = rpkt.DstHost()
		So(host, ShouldEqual, dstHost)
		So(err, ShouldBeNil)

		host, err = rpkt.DstHost()
		So(host, ShouldEqual, dstHost)
		So(err, ShouldBeNil)

		So(fetched, ShouldEqual, 1)

		host, err = rpkt.SrcHost()
		So(host, ShouldEqual, srcHost)
		So(err, ShouldBeNil)

		host, err = rpkt.SrcHost()
		So(host, ShouldEqual, srcHost)
		So(err, ShouldBeNil)

		So(fetched, ShouldEqual, 2)
	})
}

func Test_Hooks_Infof(t *testing.T) {
	rpkt := setupRtrPktHookTest()
	infof := spath.InfoField{TsInt: 10, ISD: 11, Hops: 3}

	rpkt.hooks = hooks{

		Infof: []hookInfoF{func() (HookResult, *spath.InfoField, error) {
			fetched++
			return HookFinish, &infof, nil
		}},
	}

	Convey("Fetch Infof via hook functions", t, func() {
		var info *spath.InfoField

		info, err = rpkt.InfoF()
		So(err, ShouldBeNil)

		So(info.ISD, ShouldEqual, infof.ISD)
		So(info.TsInt, ShouldEqual, infof.TsInt)
		So(info.Hops, ShouldEqual, infof.Hops)

		info, err = rpkt.InfoF()
		So(err, ShouldBeNil)

		So(info.ISD, ShouldEqual, infof.ISD)
		So(info.TsInt, ShouldEqual, infof.TsInt)
		So(info.Hops, ShouldEqual, infof.Hops)

		So(fetched, ShouldEqual, 1)
	})
}

func Test_Hooks_Hopf(t *testing.T) {
	rpkt := setupRtrPktHookTest()
	hopfield := spath.HopField{VerifyOnly: true}

	rpkt.hooks = hooks{

		HopF: []hookHopF{func() (HookResult, *spath.HopField, error) {
			fetched++
			return HookFinish, &hopfield, nil
		}},
	}

	Convey("Fetch UpFlag via hook functions", t, func() {
		var hopf *spath.HopField

		hopf, err = rpkt.HopF()
		So(hopf.VerifyOnly, ShouldEqual, hopfield.VerifyOnly)
		So(err, ShouldBeNil)

		hopf, err = rpkt.HopF()
		So(hopf.VerifyOnly, ShouldEqual, hopfield.VerifyOnly)
		So(err, ShouldBeNil)

		So(fetched, ShouldEqual, 1)
	})
}

func Test_Hooks_Up(t *testing.T) {
	rpkt := setupRtrPktHookTest()

	rpkt.hooks = hooks{

		UpFlag: []hookBool{func() (HookResult, bool, error) {
			fetched++
			return HookFinish, true, nil
		}},
	}

	Convey("Fetch UpFlag via hook functions", t, func() {
		var up *bool

		up, err = rpkt.UpFlag()
		So(*up, ShouldBeTrue)
		So(err, ShouldBeNil)

		up, err = rpkt.UpFlag()
		So(*up, ShouldBeTrue)
		So(err, ShouldBeNil)

		So(fetched, ShouldEqual, 1)
	})
}

func Test_Lifecycle(t *testing.T) {
	rpkt := setupRtrPktHookTest()

	Convey("Track references", t, func() {
		var free = false
		rpkt.Free = func(pkt *RtrPkt) {
			free = true
		}

		So(rpkt, ShouldNotBeNil)
		So(rpkt.refCnt, ShouldEqual, 1)

		rpkt.refInc(2)
		So(rpkt.refCnt, ShouldEqual, 3)

		rpkt.Release()
		So(rpkt.refCnt, ShouldEqual, 2)
		So(free, ShouldBeFalse)

		rpkt.Release()
		So(free, ShouldBeFalse)

		rpkt.Release()
		So(free, ShouldBeTrue)
		So(rpkt.refCnt, ShouldEqual, 0)

		rpkt.Reset()
		So(rpkt.refCnt, ShouldEqual, 1)
		So(rpkt.Id, ShouldBeEmpty)
	})
}
