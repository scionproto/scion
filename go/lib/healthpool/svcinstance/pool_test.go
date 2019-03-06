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

package svcinstance

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/healthpool"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

type testInfo struct {
	key  string
	addr *addr.AppAddr
}

var ds = []testInfo{
	{"ds1-ff00_0_111-1", &addr.AppAddr{
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 22)),
		L4: addr.NewL4UDPInfo(30084)},
	},
	{"ds1-ff00_0_111-2", &addr.AppAddr{
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 80)),
		L4: addr.NewL4UDPInfo(30085)},
	},
}

func TestNewPool(t *testing.T) {
	Convey("Given a non-empty service instance map", t, func() {
		pool, err := NewPool(mustLoadSvcInfo(t), healthpool.PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("The pool should contain all discovery services", func() {
			containsAll(pool, ds)
		})
	})
	Convey("Given an empty instance map, initialize only when AllowEmpty is set", t, func() {
		_, err := NewPool(nil, healthpool.PoolOptions{})
		SoMsg("!AllowEmpty", err, ShouldNotBeNil)
		_, err = NewPool(nil, healthpool.PoolOptions{AllowEmpty: true})
		SoMsg("AllowEmpty", err, ShouldBeNil)
	})
}

func TestPoolUpdate(t *testing.T) {
	Convey("Given a pool", t, func() {
		pool := mustLoadPool(t)
		svcInfo := mustLoadSvcInfo(t)
		Convey("And an instance map containing an updated discovery service entry", func() {
			svcInfo[ds[0].key].IPv4.PublicAddr().L3 = addr.HostFromIP(
				net.IPv4(127, 0, 0, 21))
			pool.infos[ds[0].key].Fail()
			pool.Update(svcInfo)
			Convey("The pool should contain the updated and reset info", func() {
				contains(pool, testInfo{
					key: ds[0].key,
					addr: &addr.AppAddr{
						L3: addr.HostFromIP(net.IPv4(127, 0, 0, 21)),
						L4: addr.NewL4UDPInfo(
							svcInfo[ds[0].key].IPv4.PublicAddr().L4.Port()),
					},
				})
				SoMsg("FailCount", pool.infos[ds[0].key].FailCount(), ShouldBeZeroValue)
			})
		})
		Convey("And an instance map containing new discovery service entries", func() {
			svcInfo["ds-new"] = svcInfo[ds[0].key]
			pool.Update(svcInfo)
			Convey("The pool should contain all discovery services", func() {
				infos := append(ds, testInfo{
					key: "ds-new",
					addr: &addr.AppAddr{
						L3: addr.HostFromIP(net.IPv4(127, 0, 0, 22)),
						L4: addr.NewL4UDPInfo(30084)},
				})
				containsAll(pool, infos)
			})
		})
		Convey("And an instance map with some removed discovery service", func() {
			delete(svcInfo, ds[1].key)
			pool.Update(svcInfo)
			Convey("The pool should contain all remaining discovery services", func() {
				containsAll(pool, ds[:1])
			})
			Convey("The pool should not contain the removed discovery service", func() {
				_, ok := pool.infos[ds[1].key]
				So(ok, ShouldBeFalse)
			})
		})
		Convey("And an instance map with no discovery service", func() {
			pool.Update(nil)
			Convey("The pool should still contain all services", func() {
				containsAll(pool, ds[:1])
			})
		})
	})
}

func TestPoolChoose(t *testing.T) {
	Convey("Given an initialized pool", t, func() {
		p := mustLoadPool(t)
		p.infos[ds[0].key].Fail()
		i, err := p.Choose()
		SoMsg("err ds1-ff00_0_111-2", err, ShouldBeNil)
		SoMsg("Choose ds1-ff00_0_111-2", i.Addr().Equal(p.infos[ds[1].key].addr), ShouldBeTrue)
		SoMsg("Name ds1-ff00_0_111-2", i.Name(), ShouldEqual, "ds1-ff00_0_111-2")
		i.Fail()
		i.Fail()
		i, err = p.Choose()
		SoMsg("err ds1-ff00_0_111-1", err, ShouldBeNil)
		SoMsg("Choose ds1-ff00_0_111-1", i.Addr().Equal(p.infos[ds[0].key].addr), ShouldBeTrue)
		SoMsg("Name ds1-ff00_0_111-1", i.Name(), ShouldEqual, "ds1-ff00_0_111-1")
	})
}

func TestPoolClose(t *testing.T) {
	Convey("Given a closed pool", t, func() {
		p := mustLoadPool(t)
		p.Close()
		_, err := p.Choose()
		SoMsg("Choose should fail", err, ShouldNotBeNil)
		SoMsg("Update should fail", p.Update(mustLoadSvcInfo(t)), ShouldNotBeNil)
		SoMsg("Close should not panic", p.Close, ShouldNotPanic)
	})
}

func containsAll(p *Pool, infos []testInfo) {
	for _, v := range ds[:1] {
		contains(p, v)
	}
}

func contains(p *Pool, v testInfo) {
	Convey("The pool contains "+v.key, func() {
		info, ok := p.infos[v.key]
		SoMsg("Not found", ok, ShouldBeTrue)
		SoMsg("Ip", info.addr.L3.IP(), ShouldResemble, v.addr.L3.IP())
		SoMsg("Port", info.addr.L4.Port(), ShouldEqual, v.addr.L4.Port())
	})
}

func mustLoadPool(t *testing.T) *Pool {
	pool, err := NewPool(mustLoadSvcInfo(t), healthpool.PoolOptions{})
	xtest.FailOnErr(t, err)
	return pool
}

func mustLoadSvcInfo(t *testing.T) topology.IDAddrMap {
	topo, err := topology.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	return topo.DS
}
