// Copyright 2021 Anapaya Systems
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

package routemgr

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
)

func createRouteDB() *RouteDB {
	db := &RouteDB{
		CleanupInterval: time.Millisecond,
	}
	go func() {
		defer log.HandlePanic()
		db.Run()
	}()
	return db
}

func TestSimple(t *testing.T) {
	db := createRouteDB()
	pub := db.NewPublisher()
	cons := db.NewConsumer()
	_, prefix, _ := net.ParseCIDR("192.168.0.0/24")
	nh := net.ParseIP("10.11.12.13")
	route := Route{Prefix: prefix, NextHop: nh}

	pub.AddRoute(route)
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)

	pub.DeleteRoute(route)
	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub.Close()
	cons.Close()
	db.Close()
}

func TestMultiple(t *testing.T) {
	db := createRouteDB()
	pub1 := db.NewPublisher()
	pub2 := db.NewPublisher()
	cons1 := db.NewConsumer()
	cons2 := db.NewConsumer()
	_, prefix1, _ := net.ParseCIDR("192.168.0.0/24")
	_, prefix2, _ := net.ParseCIDR("192.168.1.0/24")
	nh := net.ParseIP("10.11.12.13")
	route1 := Route{Prefix: prefix1, NextHop: nh}
	route2 := Route{Prefix: prefix2, NextHop: nh}

	pub1.AddRoute(route1)
	upd := <-cons1.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	upd = <-cons2.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub2.AddRoute(route2)
	upd = <-cons1.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix2, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	upd = <-cons2.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix2, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub1.DeleteRoute(route1)
	upd = <-cons1.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	upd = <-cons2.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub1.Close()
	pub2.Close()
	cons1.Close()
	cons2.Close()
	db.Close()
}

func TestPublisherRefcount(t *testing.T) {
	db := createRouteDB()
	pub := db.NewPublisher()
	cons := db.NewConsumer()
	_, prefix, _ := net.ParseCIDR("192.168.0.0/24")
	nh := net.ParseIP("10.11.12.13")
	route := Route{Prefix: prefix, NextHop: nh}

	pub.AddRoute(route)
	pub.AddRoute(route)
	pub.DeleteRoute(route)
	pub.DeleteRoute(route)

	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub.Close()
	cons.Close()
	db.Close()
}

func TestDBRefcount(t *testing.T) {
	db := createRouteDB()
	pub1 := db.NewPublisher()
	pub2 := db.NewPublisher()
	cons := db.NewConsumer()
	_, prefix, _ := net.ParseCIDR("192.168.0.0/24")
	nh := net.ParseIP("10.11.12.13")
	route := Route{Prefix: prefix, NextHop: nh}

	pub1.AddRoute(route)
	pub2.AddRoute(route)
	pub1.DeleteRoute(route)
	pub2.DeleteRoute(route)

	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub1.Close()
	pub2.Close()
	cons.Close()
	db.Close()
}

func TestPublisherClose(t *testing.T) {
	db := createRouteDB()
	pub := db.NewPublisher()
	cons := db.NewConsumer()
	_, prefix, _ := net.ParseCIDR("192.168.0.0/24")
	nh := net.ParseIP("10.11.12.13")
	route := Route{Prefix: prefix, NextHop: nh}

	pub.AddRoute(route)
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub.Close()
	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	cons.Close()
	db.Close()
}

func TestConsumerClose(t *testing.T) {
	db := createRouteDB()
	cons := db.NewConsumer()

	cons.Close()
	_, ok := <-cons.Updates()
	assert.Equal(t, false, ok)

	db.Close()
}

func TestDelayed(t *testing.T) {
	db := createRouteDB()
	pub := db.NewPublisher()
	_, prefix, _ := net.ParseCIDR("192.168.0.0/24")
	nh := net.ParseIP("10.11.12.13")
	route := Route{Prefix: prefix, NextHop: nh}

	pub.AddRoute(route)

	cons := db.NewConsumer()
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)

	pub.Close()
	cons.Close()
	db.Close()
}
