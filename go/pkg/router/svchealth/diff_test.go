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

package svchealth_test

import (
	"net"
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/pkg/router/svchealth"
)

func TestComputeDiff(t *testing.T) {
	a := &net.UDPAddr{IP: net.IP{127, 0, 0, 100}}
	b := &net.UDPAddr{IP: net.IP{127, 0, 0, 101}}
	c := &net.UDPAddr{IP: net.IP{127, 0, 0, 102}}

	testCases := map[string]struct {
		Prev map[addr.HostSVC][]*net.UDPAddr
		Next map[addr.HostSVC][]*net.UDPAddr
		Diff svchealth.Diff
	}{
		"cs added, sig removed": {
			Prev: map[addr.HostSVC][]*net.UDPAddr{
				addr.SvcCS:  {a, b},
				addr.SvcSIG: {a, b},
			},
			Next: map[addr.HostSVC][]*net.UDPAddr{
				addr.SvcCS:  {a, c, b},
				addr.SvcSIG: {a},
			},
			Diff: svchealth.Diff{
				Add:    map[addr.HostSVC][]net.IP{addr.SvcCS: {c.IP}},
				Remove: map[addr.HostSVC][]net.IP{addr.SvcSIG: {b.IP}},
			},
		},
		"cs newly discovered": {
			Prev: map[addr.HostSVC][]*net.UDPAddr{
				addr.SvcSIG: {a},
			},
			Next: map[addr.HostSVC][]*net.UDPAddr{
				addr.SvcSIG: {a},
				addr.SvcCS:  {b},
			},
			Diff: svchealth.Diff{
				Add:    map[addr.HostSVC][]net.IP{addr.SvcCS: {b.IP}},
				Remove: map[addr.HostSVC][]net.IP{},
			},
		},
		"sig no longer discovered": {
			Prev: map[addr.HostSVC][]*net.UDPAddr{
				addr.SvcSIG: {a},
			},
			Next: map[addr.HostSVC][]*net.UDPAddr{},
			Diff: svchealth.Diff{
				Add:    map[addr.HostSVC][]net.IP{},
				Remove: map[addr.HostSVC][]net.IP{addr.SvcSIG: {a.IP}},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			diff := svchealth.ComputeDiff(tc.Prev, tc.Next)
			sort := func(ips []net.IP) {
				sort.Slice(ips, func(i, j int) bool {
					return ips[i].String() < ips[j].String()
				})
			}
			for k := range diff.Add {
				sort(diff.Add[k])
			}
			for k := range diff.Remove {
				sort(diff.Add[k])
			}
			assert.Equal(t, tc.Diff, diff)
		})
	}
}
