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

	"github.com/scionproto/scion/go/lib/addr"
	. "github.com/smartystreets/goconvey/convey"
)

type testStructure struct {
	scenario string
	trc      *Trc
	err      string
}

func TestValidatingTrc(t *testing.T) {
	Convey("Given a TRC configuration", t, func() {
		tests := []testStructure{
			{
				scenario: "Empty TRC",
				trc:      &Trc{},
				err:      "Parameter 'Version' not set.",
			},
			{
				scenario: "Minimal TRC with just version number",
				trc:      &Trc{Version: 1},
				err:      "Parameter 'Validity' not set.",
			},
			{
				scenario: "TRC with version number and invalid validity duration",
				trc:      &Trc{Version: 1, RawValidity: "18"},
				err:      "Invalid validity duration duration=\"18\"",
			},
			{
				scenario: "TRC with version number and valid validity duration",
				trc:      &Trc{Version: 1, RawValidity: "180d"},
				err:      "Parameter 'CoreASes' not set.",
			},
			{
				scenario: "TRC with invalid core IAs",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs: []addr.IA{
						{
							I: addr.ISD(0),
							A: addr.AS(0),
						},
					},
				},
				err: "Invalid core AS ia=\"0-0\"",
			},
			{
				scenario: "TRC with set of CoreAS",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs: []addr.IA{
						{
							I: addr.ISD(1),
							A: addr.AS(280375465082897),
						},
					},
				},
				err: "Parameter 'QuorumTrc' not set.",
			},
			{
				scenario: "TRC with invalid Grace Period",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs: []addr.IA{
						{
							I: addr.ISD(1),
							A: addr.AS(280375465082897),
						},
					},
					RawGracePeriod: "14",
				},
				err: "Invalid validity duration duration=\"14\"",
			},
			{
				scenario: "TRC with QuorumTRC greater than number of CoreIAs",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs: []addr.IA{
						{
							I: addr.ISD(1),
							A: addr.AS(280375465082897),
						},
					},
					QuorumTRC: 2,
				},
				err: "QuorumTRC > # core ASes",
			},
			{
				scenario: "TRC with correct number of QuorumTRC",
				trc: &Trc{
					Version:     1,
					RawValidity: "180d",
					CoreIAs: []addr.IA{
						{
							I: addr.ISD(1),
							A: addr.AS(280375465082897),
						},
					},
					QuorumTRC: 1,
				},
				err: "",
			},
		}

		for _, test := range tests {
			Convey(test.scenario, func() {
				err := test.trc.validate()
				if test.err != "" {
					So(err.Error(), ShouldEqual, test.err)
				} else {
					So(err, ShouldBeNil)
				}
			})
		}
	})
}
