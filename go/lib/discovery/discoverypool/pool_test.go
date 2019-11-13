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

package discoverypool

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

type testInfo struct {
	key  string
	addr *net.UDPAddr
}

var ds = []testInfo{
	{"ds1-ff00_0_111-1", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 22),
		Port: 30084,
	},
	},
	{"ds1-ff00_0_111-2", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 80),
		Port: 30085,
	},
	},
}

func contains(pool *Pool, v testInfo) {
	Convey("The pool contains "+v.key, func() {
		info, ok := pool.m[v.key]
		SoMsg("Not found", ok, ShouldBeTrue)
		SoMsg("Ip", info.Addr().IP.Equal(v.addr.IP), ShouldBeTrue)
		SoMsg("Port", info.Addr().Port, ShouldEqual, v.addr.Port)
	})
}

func TestNew(t *testing.T) {
	Convey("Given a topology", t, func() {
		svcInfo := mustLoadSvcInfo(t)
		Convey("When the topology contains a discovery service", func() {
			pool, err := New(svcInfo)
			Convey("The pool should initialize", func() {
				So(err, ShouldBeNil)
			})
			Convey("The pool should contain all discovery services", func() {
				for _, v := range ds {
					contains(pool, v)
				}
			})
		})
		Convey("When the topology does not contain a discovery service", func() {
			Convey("The pool should not initialize", func() {
				_, err := New(nil)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestPoolUpdate(t *testing.T) {
	Convey("Given a pool", t, func() {
		pool := mustLoadPool(t)
		svcInfo := mustLoadSvcInfo(t)
		Convey("And a topology containing an updated discovery service entry", func() {
			svcInfo[ds[0].key].IPv4.PublicAddr().L3 = addr.HostFromIP(
				net.IPv4(127, 0, 0, 21))
			pool.Update(svcInfo)
			Convey("The pool should contain the updated info", func() {
				contains(pool, testInfo{
					key: ds[0].key,
					addr: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 21),
						Port: int(svcInfo[ds[0].key].IPv4.PublicAddr().L4),
					},
				})
			})
		})
		Convey("And a topology containing new discovery service entries", func() {
			svcInfo["ds-new"] = svcInfo[ds[0].key]
			pool.Update(svcInfo)
			Convey("The pool should contain all discovery services", func() {
				for _, v := range ds {
					contains(pool, v)
				}
				contains(pool, testInfo{
					key: "ds-new",
					addr: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 22),
						Port: 30084},
				})
			})
		})
		Convey("And a topology with some removed discovery service", func() {
			delete(svcInfo, ds[1].key)
			pool.Update(svcInfo)
			Convey("The pool should contain all remaining discovery services", func() {
				for _, v := range ds[:1] {
					contains(pool, v)
				}
			})
			Convey("The pool should not contain the removed discovery service", func() {
				_, ok := pool.m[ds[1].key]
				So(ok, ShouldBeFalse)
			})
		})
		Convey("And a topology with no discovery service", func() {
			pool.Update(nil)
			Convey("The pool should still contain all services", func() {
				for _, v := range ds[:1] {
					contains(pool, v)
				}
			})
		})
	})
}

func mustLoadPool(t *testing.T) *Pool {
	pool, err := New(mustLoadSvcInfo(t))
	xtest.FailOnErr(t, err)
	return pool
}

func mustLoadSvcInfo(t *testing.T) topology.IDAddrMap {
	topo, err := itopo.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	return topo.DS()
}
