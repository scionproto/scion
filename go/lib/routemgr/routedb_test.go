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
	"encoding/json"
	"flag"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// update is a cmd line flag that enables golden file updates. To update the
// golden files simply run 'go test -update ./...'.
var update = flag.Bool("update", false, "set to true to regenerate golden files")

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
	src := net.ParseIP("10.14.15.16")
	route := control.Route{Prefix: prefix, NextHop: nh, Source: src}

	pub.AddRoute(route)
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)

	pub.DeleteRoute(route)
	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

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
	src := net.ParseIP("10.14.15.16")
	route1 := control.Route{Prefix: prefix1, NextHop: nh, Source: src}
	route2 := control.Route{Prefix: prefix2, NextHop: nh, Source: src}

	pub1.AddRoute(route1)
	upd := <-cons1.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)
	upd = <-cons2.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	pub2.AddRoute(route2)
	upd = <-cons1.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix2, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)
	upd = <-cons2.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix2, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	pub1.DeleteRoute(route1)
	upd = <-cons1.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)
	upd = <-cons2.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix1, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

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
	src := net.ParseIP("10.14.15.16")
	route := control.Route{Prefix: prefix, NextHop: nh, Source: src}

	pub.AddRoute(route)
	pub.AddRoute(route)
	pub.DeleteRoute(route)
	pub.DeleteRoute(route)

	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

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
	src := net.ParseIP("10.14.15.16")
	route := control.Route{Prefix: prefix, NextHop: nh, Source: src}

	pub1.AddRoute(route)
	pub2.AddRoute(route)
	pub1.DeleteRoute(route)
	pub2.DeleteRoute(route)

	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

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
	src := net.ParseIP("10.14.15.16")
	route := control.Route{Prefix: prefix, NextHop: nh, Source: src}

	pub.AddRoute(route)
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	pub.Close()
	upd = <-cons.Updates()
	assert.Equal(t, false, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

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
	src := net.ParseIP("10.14.15.16")
	route := control.Route{Prefix: prefix, NextHop: nh, Source: src}

	pub.AddRoute(route)

	cons := db.NewConsumer()
	upd := <-cons.Updates()
	assert.Equal(t, true, upd.IsAdd)
	assert.Equal(t, prefix, upd.Prefix)
	assert.Equal(t, nh, upd.NextHop)
	assert.Equal(t, src, upd.Source)

	pub.Close()
	cons.Close()
	db.Close()
}

func TestRouteDBDiagnosticsWrite(t *testing.T) {
	db := createRouteDB()
	pub := db.NewPublisher()

	parseRoute := func(route string) control.Route {
		s := strings.Split(route, " ")
		return control.Route{
			Prefix:  xtest.MustParseCIDR(t, s[0]),
			NextHop: net.ParseIP(s[len(s)-1]),
		}
	}

	routes := []control.Route{
		parseRoute("dead::/64        deaf::beef"),
		parseRoute("dead::/65        deaf::beef"),
		parseRoute("192.168.1.0/24   10.11.12.13"),
		parseRoute("192.168.100.0/24 10.11.12.13"),
		parseRoute("192.168.25.0/24  10.11.12.13"),
		parseRoute("192.168.0.0/24   10.11.12.13"),
		parseRoute("192.168.0.128/25 10.11.12.13"),
		parseRoute("192.168.0.192/26 10.11.12.13"),
		parseRoute("192.168.1.0/24   10.11.12.14"),
		parseRoute("192.168.100.0/24 10.11.12.14"),
		parseRoute("192.168.25.0/24  10.11.12.14"),
		parseRoute("192.168.0.0/24   10.11.12.14"),
		parseRoute("192.168.0.128/25 10.11.12.14"),
		parseRoute("192.168.0.192/26 10.11.12.14"),
	}

	for _, route := range routes {
		pub.AddRoute(route)
	}

	all, err := json.MarshalIndent(db.Diagnostics(), "", "    ")
	require.NoError(t, err)
	if *update {
		xtest.MustWriteToFile(t, all, "all-routes.json")
	}
	expected := xtest.MustReadFromFile(t, "all-routes.json")
	require.Equal(t, string(expected), string(all))

	for _, route := range routes[4:] {
		pub.DeleteRoute(route)
	}
	db.cleanUp()

	remaining, err := json.MarshalIndent(db.Diagnostics(), "", "    ")
	require.NoError(t, err)
	if *update {
		xtest.MustWriteToFile(t, remaining, "remaining-routes.json")
	}
	expected = xtest.MustReadFromFile(t, "remaining-routes.json")
	require.Equal(t, string(expected), string(remaining))

	pub.Close()
	db.Close()
}
