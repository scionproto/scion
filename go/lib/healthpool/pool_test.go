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

package healthpool

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

type testInfo struct {
	Info
	name string
}

func TestNewPool(t *testing.T) {
	Convey("Given a non-empty info set", t, func() {
		_, _, infos := testInfoSet()
		p, err := NewPool(infos, PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("The pool should contain all infos", func() {
			containsAll(p, infos)
		})
	})
	Convey("Given an empty info set, initialize only when AllowEmpty is set", t, func() {
		_, err := NewPool(nil, PoolOptions{})
		SoMsg("!AllowEmpty", err, ShouldNotBeNil)
		_, err = NewPool(nil, PoolOptions{AllowEmpty: true})
		SoMsg("AllowEmpty", err, ShouldBeNil)
	})
	Convey("Given an invalid algorithm, the pool does not initialize", t, func() {
		_, err := NewPool(nil, PoolOptions{Algorithm: "invalid", AllowEmpty: true})
		SoMsg("err", err, ShouldNotBeNil)
	})
}

func TestPoolUpdate(t *testing.T) {
	Convey("Given an initialized pool", t, func() {
		_, two, infos := testInfoSet()
		p, err := NewPool(infos, PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("An added entry should be part of the pool", func() {
			cInfos := copyInfoSet(infos)
			cInfos[newTestInfo("three")] = struct{}{}
			err := p.Update(cInfos)
			SoMsg("err", err, ShouldBeNil)
			containsAll(p, cInfos)
		})
		Convey("A removed entry should no longer be part of the pool", func() {
			cInfos := copyInfoSet(infos)
			delete(cInfos, two)
			err := p.Update(cInfos)
			SoMsg("err", err, ShouldBeNil)
			containsAll(p, cInfos)
			SoMsg("Deleted entry", p.infos[two], ShouldBeNil)
		})
		Convey("An empty update should only succeed when AllowEmpty is set", func() {
			SoMsg("!AllowEmpty", p.Update(nil), ShouldNotBeNil)
			p.opts.AllowEmpty = true
			SoMsg("AllowEmpty", p.Update(nil), ShouldBeNil)
		})
	})
}

func TestPoolChoose(t *testing.T) {
	Convey("Given an initialized pool with default algorithm", t, func() {
		one, two, infos := testInfoSet()
		p, err := NewPool(infos, PoolOptions{})
		xtest.FailOnErr(t, err)
		one.Fail()
		i, err := p.Choose()
		SoMsg("err two", i, ShouldEqual, two)
		two.Fail()
		two.Fail()
		i, err = p.Choose()
		SoMsg("err one", i, ShouldEqual, one)
		two.ResetCount()
		i, err = p.Choose()
		SoMsg("err reset", i, ShouldEqual, two)
		one.(*testInfo).Info.(*info).fails = uint16(MaxFailCount)
		two.(*testInfo).Info.(*info).fails = uint16(MaxFailCount)
		_, err = p.Choose()
		SoMsg("err maxFailCount", err, ShouldBeNil)
	})
	Convey("Given an empty pool, an error is returned", t, func() {
		p, err := NewPool(nil, PoolOptions{AllowEmpty: true})
		xtest.FailOnErr(t, err)
		_, err = p.Choose()
		SoMsg("err", err, ShouldNotBeNil)
	})
}

func TestPoolClose(t *testing.T) {
	Convey("Given a closed pool", t, func() {
		_, _, infos := testInfoSet()
		p, err := NewPool(infos, PoolOptions{})
		xtest.FailOnErr(t, err)
		p.Close()
		_, err = p.Choose()
		SoMsg("Choose should fail", err, ShouldNotBeNil)
		SoMsg("Update should fail", p.Update(infos), ShouldNotBeNil)
		SoMsg("Close should not panic", p.Close, ShouldNotPanic)
	})
}

func TestPoolExpiresFails(t *testing.T) {
	Convey("The pool expires fails", t, func() {
		initTime := time.Now().Add(-(time.Hour + time.Second))
		one := &info{
			lastExp:  initTime,
			lastFail: initTime,
			fails:    64,
		}
		two := &info{
			lastExp:  initTime,
			lastFail: initTime,
			fails:    128,
		}
		infos := InfoSet{
			one: {},
			two: {},
		}
		p, err := NewPool(
			infos,
			PoolOptions{
				Expire: ExpireOptions{
					Interval: time.Hour / 2,
					Start:    time.Microsecond,
				},
			},
		)
		xtest.FailOnErr(t, err)
		p.expirer.TriggerRun()
		SoMsg("one", one.FailCount(), ShouldEqual, 16)
		SoMsg("two", two.FailCount(), ShouldEqual, 32)
	})
}

func containsAll(p *Pool, infos InfoSet) {
	for info := range infos {
		SoMsg(info.(*testInfo).name, p.infos[info], ShouldEqual, info)
	}
}

func testInfoSet() (Info, Info, InfoSet) {
	one := newTestInfo("one")
	two := newTestInfo("two")
	infos := InfoSet{
		one: {},
		two: {},
	}
	return one, two, infos
}

func newTestInfo(name string) *testInfo {
	return &testInfo{
		Info: NewInfo(),
		name: name,
	}
}

func copyInfoSet(infos InfoSet) InfoSet {
	m := make(InfoSet, len(infos))
	for info := range infos {
		m[info] = struct{}{}
	}
	return m
}
