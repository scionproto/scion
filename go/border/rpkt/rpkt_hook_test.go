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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/spath"
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

func TestHooksSrcDstIA(t *testing.T) {
	Convey("Fetch SrcIA, DstIA via hook functions", t, func() {
		rpkt := setupRtrPktHookTest()

		srcIA := addr.IA{I: 1, A: 2}
		dstIA := addr.IA{I: 3, A: 4}

		rpkt.hooks = hooks{
			SrcIA: []hookIA{func() (HookResult, addr.IA, error) {
				fetched++
				return HookFinish, srcIA, nil
			}},
			DstIA: []hookIA{func() (HookResult, addr.IA, error) {
				fetched++
				return HookFinish, dstIA, nil
			}},
		}
		var ia addr.IA

		ia, err = rpkt.DstIA()
		SoMsg("Destination address wrong", ia, ShouldResemble, dstIA)
		SoMsg("Should be no error when calling destination address getter", err, ShouldBeNil)

		ia, err = rpkt.DstIA()
		SoMsg("Destination address wrong on second getter call", ia, ShouldResemble, dstIA)
		SoMsg("Destination address must only be fetched once, cached value must be reused on the"+
			" second call", fetched, ShouldEqual, 1)
		SoMsg("Should be no error when calling destination address getter for cached value", err,
			ShouldBeNil)

		ia, err = rpkt.SrcIA()
		SoMsg("Source address wrong", ia, ShouldResemble, srcIA)
		SoMsg("Should be no error when calling source address getter", err, ShouldBeNil)

		ia, err = rpkt.SrcIA()
		SoMsg("Source address wrong on cached getter call", ia, ShouldResemble, srcIA)
		SoMsg("Should be no error when calling destination address getter for cached value", err,
			ShouldBeNil)
		SoMsg("Two fetches are expected (both source and destination address, each exactly once)",
			fetched, ShouldEqual, 2)
	})
}

func TestHooksSrcDstHost(t *testing.T) {
	Convey("Fetch SrcHost, DstHost via hook functions", t, func() {
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
		var host addr.HostAddr

		host, err = rpkt.DstHost()
		SoMsg("Destination host wrong", addr.HostEq(host, dstHost), ShouldBeTrue)
		SoMsg("Should be no error when calling destination host getter", err, ShouldBeNil)

		host, err = rpkt.DstHost()
		SoMsg("Destination host wrong on second getter call", addr.HostEq(host, dstHost), ShouldBeTrue)
		SoMsg("Should be no error when calling destination host getter for cached value", err,
			ShouldBeNil)
		SoMsg("Destination host must only be fetched once, cached value must be reused on the "+
			"second call", fetched, ShouldEqual, 1)

		host, err = rpkt.SrcHost()
		SoMsg("Source host wrong", addr.HostEq(host, srcHost), ShouldBeTrue)
		SoMsg("Should be no error when calling source host getter", err, ShouldBeNil)

		host, err = rpkt.SrcHost()
		SoMsg("Source host wrong on cached getter call", addr.HostEq(host, srcHost), ShouldBeTrue)
		SoMsg("Should be no error when calling destination host getter for cached value", err,
			ShouldBeNil)
		SoMsg("Two fetches are expected (both source and destination host, each exactly once)",
			fetched, ShouldEqual, 2)
	})
}

func TestHooksInfof(t *testing.T) {
	Convey("Fetch Infof via hook functions", t, func() {
		rpkt := setupRtrPktHookTest()
		infof := spath.InfoField{TsInt: 10, ISD: 11, Hops: 3}

		rpkt.hooks = hooks{
			Infof: []hookInfoF{func() (HookResult, *spath.InfoField, error) {
				fetched++
				return HookFinish, &infof, nil
			}},
		}
		var info *spath.InfoField

		info, err = rpkt.InfoF()
		SoMsg("Should be no error when calling InfoField getter for fetch", err, ShouldBeNil)
		SoMsg("Wrong InfoField on the fetch call", *info, ShouldResemble, infof)

		info, err = rpkt.InfoF()
		SoMsg("Should be no error when calling InfoField getter for cached value", err,
			ShouldBeNil)
		SoMsg("Wrong InfoField on the cached getter call", *info, ShouldResemble, infof)
		SoMsg("Regardless of the two calls, only one fetch of InfoField expected", fetched,
			ShouldEqual, 1)
	})
}

func TestHooksHopf(t *testing.T) {
	Convey("Fetch HopF via hook functions", t, func() {
		rpkt := setupRtrPktHookTest()
		hopfield := spath.HopField{VerifyOnly: true}

		rpkt.hooks = hooks{
			HopF: []hookHopF{func() (HookResult, *spath.HopField, error) {
				fetched++
				return HookFinish, &hopfield, nil
			}},
		}
		var hopf *spath.HopField

		hopf, err = rpkt.HopF()
		SoMsg("Wrong HopF on the fetch call", hopf.VerifyOnly, ShouldEqual, hopfield.VerifyOnly)
		SoMsg("Should be no error when calling HopF for fetch", err, ShouldBeNil)

		hopf, err = rpkt.HopF()
		SoMsg("Wrong HopF on the cached getter call", hopf.VerifyOnly, ShouldEqual,
			hopfield.VerifyOnly)
		SoMsg("Should be no error when calling HopF getter for cached value", err, ShouldBeNil)
		SoMsg("Regardless of the two calls, only one fetch of HopF expected", fetched,
			ShouldEqual, 1)
	})
}

func TestHooksUp(t *testing.T) {
	Convey("Fetch ConsDirFlag via hook functions", t, func() {
		rpkt := setupRtrPktHookTest()
		rpkt.hooks = hooks{
			ConsDirFlag: []hookBool{func() (HookResult, bool, error) {
				fetched++
				return HookFinish, false, nil
			}},
		}
		var consDir *bool

		consDir, err = rpkt.ConsDirFlag()
		SoMsg("Wrong ConsDirFlag on the fetch call", *consDir, ShouldBeFalse)
		SoMsg("Should be no error when calling ConsDirFlag for fetch", err, ShouldBeNil)

		consDir, err = rpkt.ConsDirFlag()
		SoMsg("Wrong ConsDirFlag on the cached getter call", *consDir, ShouldBeFalse)
		SoMsg("Should be no error when calling ConsDirFlag getter for cached value", err, ShouldBeNil)
		SoMsg("Regardless of the two calls, only one fetch of ConsDirFlag expected", fetched,
			ShouldEqual, 1)
	})
}

func TestLifecycle(t *testing.T) {
	Convey("Track references", t, func() {
		rpkt := setupRtrPktHookTest()
		var free = false
		rpkt.Free = func(pkt *RtrPkt) {
			free = true
		}
		SoMsg("Must be created with one ref count", rpkt.refCnt, ShouldEqual, 1)

		rpkt.RefInc(2)
		SoMsg("RefInc() must increment ref coount from 1 by 2", rpkt.refCnt, ShouldEqual, 3)

		rpkt.Release()
		SoMsg("Release() must decrement ref count from 3 to 2", rpkt.refCnt, ShouldEqual, 2)
		SoMsg("Not freed yet, 2 refs remaining", free, ShouldBeFalse)

		rpkt.Release()
		SoMsg("Not freed yet, 1 ref remaining", free, ShouldBeFalse)

		rpkt.Release()
		SoMsg("Should be no more refs remaining by now", rpkt.refCnt, ShouldEqual, 0)
		SoMsg("Freed due to no refs remaining", free, ShouldBeTrue)

		rpkt.Reset()
		SoMsg("Reset() must set refcount to 1", rpkt.refCnt, ShouldEqual, 1)
		SoMsg("Reset() must set id to empty", rpkt.Id, ShouldBeEmpty)
	})
}
