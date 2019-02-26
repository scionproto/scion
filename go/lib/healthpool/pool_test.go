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

func TestNew(t *testing.T) {
	Convey("Given a non-empty info map", t, func() {
		infos := InfoMap{
			"one": NewInfo(),
			"two": NewInfo(),
		}
		p, err := NewPool(infos, PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("The pool should contain all infos", func() {
			containsAll(p.(*pool), infos)
		})
	})
	Convey("Given an empty info map, initialize only when AllowEmpty is set", t, func() {
		_, err := NewPool(nil, PoolOptions{})
		SoMsg("!AllowEmpty", err, ShouldNotBeNil)
		_, err = NewPool(nil, PoolOptions{AllowEmpty: true})
		SoMsg("AllowEmpty", err, ShouldBeNil)
	})
}

func TestPoolUpdate(t *testing.T) {
	Convey("Given an initialized pool", t, func() {
		infos := InfoMap{
			"one": NewInfo(),
			"two": NewInfo(),
		}
		p, err := NewPool(infos, PoolOptions{})
		SoMsg("err", err, ShouldBeNil)
		Convey("An updated entry should be part of the pool", func() {
			cInfos := copyInfoMap(infos)
			cInfos["two"] = NewInfo()
			err := p.Update(cInfos)
			SoMsg("err", err, ShouldBeNil)
			containsAll(p.(*pool), cInfos)
		})
		Convey("An added entry should be part of the pool", func() {
			cInfos := copyInfoMap(infos)
			cInfos["three"] = NewInfo()
			err := p.Update(cInfos)
			SoMsg("err", err, ShouldBeNil)
			containsAll(p.(*pool), cInfos)
		})
		Convey("A removed entry should no longer be part of the pool", func() {
			cInfos := copyInfoMap(infos)
			delete(cInfos, "two")
			err := p.Update(cInfos)
			SoMsg("err", err, ShouldBeNil)
			containsAll(p.(*pool), cInfos)
			SoMsg("Deleted entry", p.(*pool).infos["two"], ShouldBeNil)
		})
		Convey("An empty update should only succeed when AllowEmpty is set", func() {
			SoMsg("!AllowEmpty", p.Update(nil), ShouldNotBeNil)
			p.(*pool).opts.AllowEmpty = true
			SoMsg("AllowEmpty", p.Update(nil), ShouldBeNil)
		})
	})
}

func TestPoolChoose(t *testing.T) {
	Convey("Given an initialized pool with default algorithm", t, func() {
		infos := InfoMap{
			"one": NewInfo(),
			"two": NewInfo(),
		}
		p, err := NewPool(infos, PoolOptions{})
		xtest.FailOnErr(t, err)
		infos["one"].Fail()
		i, err := p.Choose()
		SoMsg("err two", i, ShouldEqual, infos["two"])
		infos["two"].Fail()
		infos["two"].Fail()
		i, err = p.Choose()
		SoMsg("err one", i, ShouldEqual, infos["one"])
		infos["one"].(*info).fails = uint16(MaxFailCount)
		infos["two"].(*info).fails = uint16(MaxFailCount)
		_, err = p.Choose()
		SoMsg("err maxFailCount", err, ShouldBeNil)
	})
}

func TestPoolExpiresFails(t *testing.T) {
	Convey("The pool expires fails", t, func() {
		initTime := time.Now().Add(-time.Second)
		infos := InfoMap{
			"one": &info{
				lastExp:  initTime,
				lastFail: initTime,
				fails:    64,
			},
			"two": &info{
				lastExp:  initTime,
				lastFail: initTime,
				fails:    64,
			},
		}
		p, err := NewPool(
			infos,
			PoolOptions{
				Expire: ExpireOptions{
					Interval: time.Second / 2,
					Start:    time.Microsecond,
				},
			},
		)
		xtest.FailOnErr(t, err)
		infos["one"].(*info).fails = 64
		infos["two"].(*info).fails = 64
		infos["one"].(*info).lastFail = time.Now().Add(-time.Second)
		infos["two"].(*info).lastFail = time.Now().Add(-time.Second)
		p.(*pool).expirer.TriggerRun()
		SoMsg("one", infos["one"].FailCount(), ShouldEqual, 16)
		SoMsg("two", infos["two"].FailCount(), ShouldEqual, 16)
	})
}

func containsAll(p *pool, infos InfoMap) {
	for key, info := range infos {
		SoMsg(string(key), p.infos[key], ShouldEqual, info)
	}
}

func copyInfoMap(infos InfoMap) InfoMap {
	m := make(InfoMap, len(infos))
	for key, info := range infos {
		m[key] = info
	}
	return m
}
