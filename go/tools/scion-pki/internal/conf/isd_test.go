// Copyright 2018 ETH Zurich
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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

type testStructure struct {
	scenario string
	trc      *Trc
	err      string
}

var coreIA = []addr.IA{xtest.MustParseIA("1-ff00:0:10")}

func TestValidatingTrc(t *testing.T) {
	Convey("Given a TRC configuration", t, func() {
		tests := []testStructure{
			{
				scenario: "Empty TRC",
				trc: &Trc{
					RawValidity: "18d",
					CoreIAs:     coreIA,
					QuorumTRC:   1,
				},
				err: ErrTrcVersionNotSet,
			},
			{
				scenario: "Minimal TRC with just version number",
				trc: &Trc{
					Version:   1,
					CoreIAs:   coreIA,
					QuorumTRC: 1,
				},
				err: ErrValidityDurationNotSet,
			},
			{
				scenario: "TRC with version number and invalid validity duration",
				trc: &Trc{
					Version:     1,
					RawValidity: "18",
					CoreIAs:     coreIA,
					QuorumTRC:   1,
				},
				err: ErrInvalidValidityDuration,
			},
			{
				scenario: "TRC with version number and valid validity duration",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					QuorumTRC:   1,
				},
				err: ErrCoreIANotSet,
			},
			{
				scenario: "TRC with invalid core IAs",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs:     []addr.IA{xtest.MustParseIA("0-0")},
					QuorumTRC:   1,
				},
				err: ErrInvalidCoreIA,
			},
			{
				scenario: "TRC with set of CoreAS",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs:     coreIA,
				},
				err: ErrQuorumTrcNotSet,
			},
			{
				scenario: "TRC with invalid Grace Period",
				trc: &Trc{
					Version:        1,
					RawValidity:    "180d",
					CoreIAs:        coreIA,
					RawGracePeriod: "14",
					QuorumTRC:      1,
				},
				err: ErrInvalidGracePeriod,
			},
			{
				scenario: "TRC with QuorumTRC greater than number of CoreIAs",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs:     coreIA,
					QuorumTRC:   2,
				},
				err: ErrQuorumTrcGreaterThanCoreIA,
			},
			{
				scenario: "TRC with correct number of QuorumTRC",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs:     coreIA,
					QuorumTRC:   1,
				},
				err: "",
			},
		}

		for _, test := range tests {
			Convey(test.scenario, func() {
				err := test.trc.validate()
				if test.err != "" {
					be := err.(common.BasicError)
					So(be.Msg, ShouldEqual, test.err)
				} else {
					So(err, ShouldBeNil)
				}
			})
		}
	})
}
