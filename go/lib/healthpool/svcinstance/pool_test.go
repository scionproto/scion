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

const (
	ds1        = "ds1-ff00_0_111-1"
	ds1updated = "ds1-ff00_0_111-1-updated"
	ds2        = "ds1-ff00_0_111-2"
	ds3new     = "ds1-ff00_0_111-3-new"
)

var dsInfos = map[string]*addr.AppAddr{
	ds1: {
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 22)),
		L4: addr.NewL4UDPInfo(30084)},
	ds2: {
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 80)),
		L4: addr.NewL4UDPInfo(30085)},
	ds3new: {
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 22)),
		L4: addr.NewL4UDPInfo(30084),
	},
	ds1updated: {
		L3: addr.HostFromIP(net.IPv4(127, 0, 0, 21)),
		L4: addr.NewL4UDPInfo(30084),
	},
}

func TestNewPool(t *testing.T) {
	Convey("Given a non-empty service instance map", t, func() {
		pool, err := NewPool(mustLoadSvcInfo(t), healthpool.PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("The pool should contain all discovery services", func() {
			containsAll(pool, ds1, ds2)
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
			svcInfo[ds1].IPv4.PublicAddr().L3 = dsInfos[ds1updated].L3
			pool.infos[ds1].Fail()
			err := pool.Update(svcInfo)
			SoMsg("err", err, ShouldBeNil)
			Convey("The pool should contain the updated and reset info", func() {
				contains(pool, ds1, dsInfos[ds1updated])
				SoMsg("FailCount", pool.infos[ds1].FailCount(), ShouldBeZeroValue)
			})
		})
		Convey("And an instance map containing new discovery service entries", func() {
			svcInfo[ds3new] = svcInfo[ds1]
			err := pool.Update(svcInfo)
			SoMsg("err", err, ShouldBeNil)
			Convey("The pool should contain all discovery services", func() {
				containsAll(pool, ds1, ds2, ds3new)
			})
		})
		Convey("And an instance map with some removed discovery service", func() {
			delete(svcInfo, ds2)
			err := pool.Update(svcInfo)
			SoMsg("err", err, ShouldBeNil)
			Convey("The pool should contain all remaining discovery services", func() {
				containsAll(pool, ds1)
			})
			Convey("The pool should not contain the removed discovery service", func() {
				_, ok := pool.infos[ds2]
				So(ok, ShouldBeFalse)
			})
		})
		Convey("And an instance map with no discovery service", func() {
			err := pool.Update(nil)
			SoMsg("err", err, ShouldNotBeNil)
			Convey("The pool should still contain all services", func() {
				containsAll(pool, ds1, ds2)
			})
		})
	})
}

func TestPoolChoose(t *testing.T) {
	Convey("Given an initialized pool", t, func() {
		p := mustLoadPool(t)
		p.infos[ds1].Fail()
		i, err := p.Choose()
		SoMsg("err first", err, ShouldBeNil)
		SoMsg("Choose first", i.Addr().Equal(p.infos[ds2].addr), ShouldBeTrue)
		SoMsg("Name first", i.Name(), ShouldEqual, ds2)
		i.Fail()
		i.Fail()
		i, err = p.Choose()
		SoMsg("err second", err, ShouldBeNil)
		SoMsg("Choose second", i.Addr().Equal(p.infos[ds1].addr), ShouldBeTrue)
		SoMsg("Name second", i.Name(), ShouldEqual, ds1)
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

func containsAll(p *Pool, names ...string) {
	for _, name := range names {
		contains(p, name, dsInfos[name])
	}
}

func contains(p *Pool, name string, a *addr.AppAddr) {
	Convey("The pool contains "+name, func() {
		info, ok := p.infos[name]
		SoMsg("Not found", ok, ShouldBeTrue)
		SoMsg("Ip", info.addr.L3.IP(), ShouldResemble, a.L3.IP())
		SoMsg("Port", info.addr.L4.Port(), ShouldEqual, a.L4.Port())
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
