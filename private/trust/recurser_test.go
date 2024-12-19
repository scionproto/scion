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

package trust_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/trust"
)

func TestASLocalRecurserAllowRecursion(t *testing.T) {
	ia110 := addr.MustParseIA("1-ff00:0:110")
	ia120 := addr.MustParseIA("1-ff00:0:120")

	tests := map[string]struct {
		Addr      net.Addr
		Assertion assert.ErrorAssertionFunc
	}{
		"host local": {
			Assertion: assert.NoError,
		},
		"AS local TCP": {
			Addr:      &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 404},
			Assertion: assert.NoError,
		},
		"AS local": {
			Addr:      &snet.UDPAddr{IA: ia110},
			Assertion: assert.NoError,
		},
		"remote AS": {
			Addr:      &snet.UDPAddr{IA: ia120},
			Assertion: assert.Error,
		},
		"invalid Address": {
			Addr:      &net.IPAddr{IP: net.IP{127, 0, 0, 1}},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := trust.ASLocalRecurser{IA: ia110}
			err := r.AllowRecursion(test.Addr)
			test.Assertion(t, err)
		})
	}
}

func TestLocalOnlyRecurserAllowRecursion(t *testing.T) {
	ia110 := addr.MustParseIA("1-ff00:0:110")
	ia120 := addr.MustParseIA("1-ff00:0:120")

	tests := map[string]struct {
		Addr      net.Addr
		Assertion assert.ErrorAssertionFunc
	}{
		"host local": {
			Assertion: assert.NoError,
		},
		"AS local": {
			Addr:      &snet.UDPAddr{IA: ia110},
			Assertion: assert.Error,
		},
		"remote AS": {
			Addr:      &snet.UDPAddr{IA: ia120},
			Assertion: assert.Error,
		},
		"invalid Address": {
			Addr:      &net.IPAddr{IP: net.IP{127, 0, 0, 1}},
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := trust.LocalOnlyRecurser{}
			err := r.AllowRecursion(test.Addr)
			test.Assertion(t, err)
		})
	}
}
