// Copyright 2023 SCION Association
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

package addr_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
)

func TestParseSVC(t *testing.T) {
	invalid := []string{
		"",
		"garbage",
		"CS_Y",
		"cs_a",
		"cs_m",
		"CS ",
		" CS",
	}
	for _, src := range invalid {
		t.Run(src, func(t *testing.T) {
			_, err := addr.ParseSVC(src)
			assert.Error(t, err)
		})
	}

	valid := map[string]addr.SVC{
		"CS":         addr.SvcCS,
		"DS":         addr.SvcDS,
		"Wildcard":   addr.SvcWildcard,
		"CS_A":       addr.SvcCS,
		"DS_A":       addr.SvcDS,
		"Wildcard_A": addr.SvcWildcard,
		"CS_M":       addr.SvcCS.Multicast(),
		"DS_M":       addr.SvcDS.Multicast(),
		"Wildcard_M": addr.SvcWildcard.Multicast(),
	}
	for src, svc := range valid {
		t.Run(src, func(t *testing.T) {
			v, err := addr.ParseSVC(src)
			assert.NoError(t, err)
			assert.Equal(t, svc, v)
		})
	}
}

func TestSVCString(t *testing.T) {
	cases := map[addr.SVC]string{
		addr.SVC(0xABC):              "<SVC:0x0abc>",
		addr.SvcCS:                   "CS",
		addr.SvcCS.Multicast():       "CS_M",
		addr.SvcDS:                   "DS",
		addr.SvcDS.Multicast():       "DS_M",
		addr.SvcWildcard:             "Wildcard",
		addr.SvcWildcard.Multicast(): "Wildcard_M",
	}
	for svc, expected := range cases {
		t.Run(expected, func(t *testing.T) {
			actual := svc.String()
			assert.Equal(t, expected, actual)
		})
	}
}
