// Copyright 2020 Anapaya Systems
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

package router_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/pkg/router"
)

func TestServicesAddSvc(t *testing.T) {
	host1 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1337}
	host2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1337}
	host1Port := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1338}
	all := []*net.UDPAddr{host1, host2, host1Port}

	s := router.NewServices()
	s.AddSvc(addr.SvcCS, host1)
	s.AddSvc(addr.SvcCS, host2)
	s.AddSvc(addr.SvcCS, host1Port)
	assert.ElementsMatch(t, all, router.ExtractServices(s)[addr.SvcCS])

	s.AddSvc(addr.SvcDS, host1)
	assert.ElementsMatch(t, []*net.UDPAddr{host1}, router.ExtractServices(s)[addr.SvcDS])
	assert.ElementsMatch(t, all, router.ExtractServices(s)[addr.SvcCS])
}

func TestServiceDelSvc(t *testing.T) {
	host1 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1337}
	host2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1337}
	all := []*net.UDPAddr{host1, host2}

	s := router.NewServices()
	assert.NotPanics(t, func() { s.DelSvc(addr.SvcCS, host1) })

	s.AddSvc(addr.SvcCS, host1)
	s.AddSvc(addr.SvcCS, host2)
	assert.ElementsMatch(t, all, router.ExtractServices(s)[addr.SvcCS])

	s.DelSvc(addr.SvcCS, host2)
	assert.ElementsMatch(t, []*net.UDPAddr{host1}, router.ExtractServices(s)[addr.SvcCS])
}

func TestServicesAny(t *testing.T) {
	host1 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1337}
	host2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1337}

	s := router.NewServices()
	s.AddSvc(addr.SvcCS, host1)
	s.AddSvc(addr.SvcCS, host2)

	var got []*net.UDPAddr
	for len(got) < 2 {
		a, ok := s.Any(addr.SvcCS)
		assert.True(t, ok)
		got = append(got, a)
	}
	assert.ElementsMatch(t, []*net.UDPAddr{host1, host2}, router.ExtractServices(s)[addr.SvcCS])
}
