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

package healthpool

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFail(t *testing.T) {
	Convey("The fail count should increase correctly", t, func() {
		info := info{}
		Convey("Increment by one when smaller than MaxFailCount", func() {
			SoMsg("Initial FailCount", info.FailCount(), ShouldEqual, 0)
			info.Fail()
			SoMsg("FailCount", info.FailCount(), ShouldEqual, 1)
		})
		Convey("Stay the same when equal than MaxFailCount", func() {
			info.fails = uint16(MaxFailCount)
			info.Fail()
			SoMsg("FailCount", info.FailCount(), ShouldEqual, MaxFailCount)
		})
	})
}

func TestExpireFails(t *testing.T) {
	Convey("The fail count should expire correctly", t, func() {
		initFails := uint16(64)
		now := time.Now()
		t := []struct {
			desc     string
			lastFail time.Time
			lastExp  time.Time
			opts     ExpireOptions
			expFails uint16
		}{
			{
				desc:     "No expiration when time since lastFail is less than start",
				lastFail: now,
				expFails: initFails,
			},
			{
				desc:     "Expiration when time since lastFail is equal to start",
				lastFail: now.Add(-DefaultExpireStart),
				expFails: initFails >> 1,
			},
			{
				desc:     "Expiration when time since lastFail is equal to start + interval",
				lastFail: now.Add(-(DefaultExpireStart + DefaultExpireInterval)),
				expFails: initFails >> 2,
			},
			{
				desc:     "Expiration when time since lastFail is equal to start + 2 intervals",
				lastFail: now.Add(-(DefaultExpireStart + 2*DefaultExpireInterval)),
				expFails: initFails >> 3,
			},
			{
				desc:     "No expiration when time since lastExp less than interval",
				lastFail: now.Add(-(DefaultExpireStart + 5*DefaultExpireInterval)),
				lastExp:  now.Add(-DefaultExpireInterval + time.Second),
				expFails: initFails,
			},
			{
				desc:     "Expiration when time since lastExp is equal to interval",
				lastFail: now.Add(-(DefaultExpireStart + 5*DefaultExpireInterval)),
				lastExp:  now.Add(-DefaultExpireInterval),
				expFails: initFails >> 1,
			},
			{
				desc:     "Expiration when time since lastExp is equal to 2 intervals",
				lastFail: now.Add(-(DefaultExpireStart + 5*DefaultExpireInterval)),
				lastExp:  now.Add(-2 * DefaultExpireInterval),
				expFails: initFails >> 2,
			},
		}
		for _, v := range t {
			Convey(v.desc, func() {
				inf := &info{
					lastFail: v.lastFail,
					lastExp:  v.lastExp,
					fails:    initFails,
				}
				inf.expireFails(now, ExpireOptions{})
				SoMsg("FailCount", inf.FailCount(), ShouldEqual, v.expFails)
			})
		}
	})
}
