// Copyright 2018 ETH Zurich
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

package conf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestValidatingTrc(t *testing.T) {
	var coreIA = []addr.IA{xtest.MustParseIA("1-ff00:0:10")}
	tests := map[string]struct {
		trc *Trc
		err string
	}{
		"Empty TRC": {
			trc: &Trc{
				RawValidity: "18d",
				CoreIAs:     coreIA,
				QuorumTRC:   1,
			},
			err: ErrTrcVersionNotSet,
		},
		"Minimal TRC with just version number": {
			trc: &Trc{
				Version:   1,
				CoreIAs:   coreIA,
				QuorumTRC: 1,
			},
			err: ErrValidityDurationNotSet,
		},
		"TRC with version number and invalid validity duration": {
			trc: &Trc{
				Version:     1,
				RawValidity: "18",
				CoreIAs:     coreIA,
				QuorumTRC:   1,
			},
			err: ErrInvalidValidityDuration,
		},
		"TRC with version number and valid validity duration": {
			trc: &Trc{
				Version:     1,
				RawValidity: "180d",
				QuorumTRC:   1,
			},
			err: ErrCoreIANotSet,
		},
		"TRC with invalid core IAs": {
			trc: &Trc{
				Version:     1,
				RawValidity: "180d",
				CoreIAs:     []addr.IA{xtest.MustParseIA("0-0")},
				QuorumTRC:   1,
			},
			err: ErrInvalidCoreIA,
		},
		"TRC with set of CoreAS": {
			trc: &Trc{
				Version:     1,
				RawValidity: "180d",
				CoreIAs:     coreIA,
			},
			err: ErrQuorumTrcNotSet,
		},
		"TRC with invalid Grace Period": {
			trc: &Trc{
				Version:        1,
				RawValidity:    "180d",
				CoreIAs:        coreIA,
				RawGracePeriod: "14",
				QuorumTRC:      1,
			},
			err: ErrInvalidGracePeriod,
		},
		"TRC with QuorumTRC greater than number of CoreIAs": {
			trc: &Trc{
				Version:     1,
				RawValidity: "180d",
				CoreIAs:     coreIA,
				QuorumTRC:   2,
			},
			err: ErrQuorumTrcGreaterThanCoreIA,
		},
		"TRC with correct number of QuorumTRC": {
			trc: &Trc{
				Version:     1,
				RawValidity: "180d",
				CoreIAs:     coreIA,
				QuorumTRC:   1,
			},
			err: "",
		},
	}

	for scenario, test := range tests {
		t.Run(scenario, func(t *testing.T) {
			err := test.trc.validate()
			if test.err != "" {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), test.err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
