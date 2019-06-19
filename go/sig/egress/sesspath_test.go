// Copyright 2019 ETH Zurich, Anapaya Systems
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

package egress

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	t0  = time.Unix(0, 0)
	t1  = time.Unix(1, 0)
	t2  = time.Unix(2, 0)
	t3  = time.Unix(3, 0)
	t4  = time.Unix(4, 0)
	t5  = time.Unix(5, 0)
	t6  = time.Unix(6, 0)
	t7  = time.Unix(7, 0)
	t8  = time.Unix(8, 0)
	t9  = time.Unix(9, 0)
	t59 = time.Unix(59, 0)
	t75 = time.Unix(75, 0)
	t80 = time.Unix(80, 0)
	t99 = time.Unix(99, 0)
)

func Test_Stats(t *testing.T) {
	Convey("New path", t, func() {
		sp := NewSessPath("", nil)
		stats := sp.Stats()
		So(stats.Latency, ShouldEqual, 0*time.Second)
		So(stats.Jitter, ShouldEqual, 0*time.Second)
		So(stats.DropRate, ShouldEqual, 1)
	})
	Convey("No drops", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t0, &t1, t59) // 1s
		sp.updateStats(&t1, &t4, t59) // 3s
		sp.updateStats(&t2, &t4, t59) // 2s
		sp.updateStats(&t3, &t8, t59) // 5s
		sp.updateStats(&t4, &t8, t59) // 4s
		So(sp.stats.Latency, ShouldEqual, 3*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 2*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0)
	})
	Convey("Some drops", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t0, &t1, t59) // 1s
		sp.updateStats(&t1, nil, t59) // timeout
		sp.updateStats(&t2, &t5, t59) // 3s
		sp.updateStats(&t3, &t8, t59) // 5s
		sp.updateStats(&t4, nil, t59) // timeout
		So(sp.stats.Latency, ShouldEqual, 3*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 2*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0.4)
	})
	Convey("All drops", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t1, nil, t59) // timeout
		sp.updateStats(&t2, nil, t59) // timeout
		sp.updateStats(&t3, nil, t59) // timeout
		So(sp.stats.Latency, ShouldEqual, 0*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 0*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 1)
	})
	Convey("Some expired probes", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t0, &t1, t59)   // 1s - should expire
		sp.updateStats(&t1, &t2, t59)   // 1s - should expire
		sp.updateStats(&t2, nil, t59)   // timeout - should expire
		sp.updateStats(&t75, &t80, t99) // 5s
		So(sp.stats.Latency, ShouldEqual, 5*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 0*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0)
	})
	Convey("All expired probes", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t0, &t1, t59) // 1s - should expire
		sp.updateStats(&t1, &t2, t59) // 1s - should expire
		sp.updateStats(nil, nil, t99)
		So(sp.stats.Latency, ShouldEqual, 0*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 0*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 1)
	})
	Convey("Backfill", t, func() {
		sp := NewSessPath("", nil)
		sp.updateStats(&t0, &t1, t1) // 1s
		sp.updateStats(&t1, nil, t2) // timeout
		sp.updateStats(&t2, &t3, t3) // 1s
		sp.updateStats(&t3, nil, t4) // timeout
		So(sp.stats.Latency, ShouldEqual, 1*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 0*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0.5)
		sp.updateStats(&t1, &t5, t5) // 4s
		So(sp.stats.Latency, ShouldEqual, 1*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 3*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0.25)
		sp.updateStats(&t3, &t6, t6) // 3s
		So(sp.stats.Latency, ShouldEqual, 3*time.Second)
		So(sp.stats.Jitter, ShouldEqual, 1*time.Second)
		So(sp.stats.DropRate, ShouldEqual, 0)
	})
}
